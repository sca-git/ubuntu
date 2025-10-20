#!/usr/bin/env bash
set -Eeuo pipefail

# ubuntu-config.sh (Planning-first, then non-interactive execution)
# - Detect ESP (vfat) and Btrfs root partitions.
# - Plan: gather all choices up front (menus and inputs), single confirmation.
# - Execute: convert root to LUKS2 (if needed), open with chosen mapper name.
# - Mount subvolumes (@, @home, @snapshots; @swap only if Btrfs swap selected).
# - Configure swap: Btrfs swapfile or zRAM; hibernation optional only with Btrfs.
# - Install systemd-boot; build UKI via kernel-install + ukify; initramfs via dracut.
# - Put Linux Boot Manager first in boot order.
# - All user prompts occur only at the beginning.

LANG=C
MNT="/mnt/target"
EFI_MNT="/efi"
MAPPER_NAME="root"
KEYSLOT_SIZE="32M"
TS="$(date +%Y%m%d-%H%M%S)"
LOGFILE="/root/ubuntu-config-${TS}.log"
TTY_IN="/dev/tty"

# Bind user-facing output to fd 3; logs to file
exec 3>&1 4>&2
exec >>"$LOGFILE" 2>&1

# Colors/icons
if command -v tput >/dev/null 2>&1 && [ -t 3 ]; then
  C_RESET="$(tput sgr0)"; C_BOLD="$(tput bold)"; C_DIM="$(tput dim)"
  C_RED="$(tput setaf 1)"; C_GREEN="$(tput setaf 2)"; C_YELLOW="$(tput setaf 3)"
  C_BLUE="$(tput setaf 4)"; C_MAGENTA="$(tput setaf 5)"; C_CYAN="$(tput setaf 6)"
else
  C_RESET=""; C_BOLD=""; C_DIM=""
  C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_MAGENTA=""; C_CYAN=""
fi
ICON_INFO="➜"; ICON_OK="✔"; ICON_WARN="⚠"; ICON_ERR="✖"; ICON_STEP="•"
log()   { printf "%b\n" "${C_CYAN}${ICON_INFO}${C_RESET} $*" >&3; }
step()  { printf "%b\n" "${C_MAGENTA}${ICON_STEP}${C_RESET} ${C_BOLD}$*${C_RESET}" >&3; }
ok()    { printf "%b\n" "${C_GREEN}${ICON_OK}${C_RESET} $*" >&3; }
warn()  { printf "%b\n" "${C_YELLOW}${ICON_WARN}${C_RESET} $*" >&3; }
err()   { printf "%b\n" "${C_RED}${ICON_ERR}${C_RESET} $*" >&3; }
die()   { err "$*"; exit 1; }

# Minimal runner with spinner
SPIN_PID=""
spinner_start() {
  local msg="$1"
  printf "%b" "${C_BLUE}${ICON_INFO}${C_RESET} ${msg} ${C_DIM}" >&3
  local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  (
    i=0
    while :; do
      i=$(( (i+1) % ${#frames} ))
      printf "\r%b" "${C_BLUE}${ICON_INFO}${C_RESET} ${msg} ${C_DIM}${frames:i:1}${C_RESET}   " >&3
      sleep 0.08
    done
  ) &
  SPIN_PID=$!
  disown "$SPIN_PID" 2>/dev/null || true
}
spinner_stop() {
  local rc="$1" msg_ok="$2" msg_err="$3"
  if [ -n "${SPIN_PID:-}" ] && kill -0 "$SPIN_PID" 2>/dev/null; then
    kill "$SPIN_PID" 2>/dev/null || true
    wait "$SPIN_PID" >/dev/null 2>&1 || true
  fi
  if [ "$rc" -eq 0 ]; then
    printf "\r%b\n" "${C_GREEN}${ICON_OK}${C_RESET} ${msg_ok}" >&3
  else
    printf "\r%b\n" "${C_RED}${ICON_ERR}${C_RESET} ${msg_err}" >&3
  fi
  SPIN_PID=""
}
run() {
  local msg="$1"; shift
  spinner_start "$msg"
  "$@" >>"$LOGFILE" 2>&1
  local rc=$?
  spinner_stop "$rc" "$msg" "$msg (failed, see $LOGFILE)"
  return $rc
}

# Read helpers (always read from TTY)
read_line() { local var; IFS= read -r var < "$TTY_IN"; echo "$var"; }
ask_input() {
  local title="$1" text="$2" default="$3"
  printf "%b" "${C_BOLD}${title}:${C_RESET} $text [$default] " >&3
  local ans; ans="$(read_line)"
  echo "${ans:-$default}"
}
ask_yes_no() {
  local title="$1" text="$2" default="${3:-no}"
  local defhint="[y/N]"; [ "$default" = "yes" ] && defhint="[Y/n]"
  printf "%b" "${C_BOLD}${title}:${C_RESET} $text ${defhint} " >&3
  local ans; ans="$(read_line)"
  [[ "$ans" =~ ^[Yy]$ ]] && echo "yes" || { [ "$default" = "yes" ] && echo "yes" || echo "no"; }
}
ask_password_confirm() {
  local title="$1" text="$2"
  printf "%b" "${C_BOLD}${title}:${C_RESET} $text " >&3
  local p1; IFS= read -rs p1 < "$TTY_IN"; printf "\n" >&3
  printf "%b" "Confirm passphrase: " >&3
  local p2; IFS= read -rs p2 < "$TTY_IN"; printf "\n" >&3
  [ -n "${p1:-}" ] && [ "$p1" = "${p2:-}" ] || die "Passphrases do not match or are empty."
  echo "$p1"
}
ask_menu() {
  # args: title, text, "tag:desc"...
  local title="$1" text="$2"; shift 2
  local -a items=("$@")
  log "$text"
  local idx=0
  for item in "${items[@]}"; do
    printf "%b\n" "  [$idx] ${item%%:*} — ${item#*:}" >&3
    idx=$((idx+1))
  done
  local sel
  while :; do
    printf "%b" "${C_BOLD}${title}:${C_RESET} Enter choice index (0-$((idx-1))): " >&3
    sel="$(read_line)"
    if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 0 ] && [ "$sel" -lt "$idx" ]; then
      echo "${items[$sel]%%:*}"
      return
    fi
    warn "Invalid selection."
  done
}

# Un/mount helpers
umount_if_mounted() {
  local target="$1"
  findmnt -rno TARGET "$target" >/dev/null 2>&1 || return 0
  run "Unmount ${target}" umount -R "$target" || true
}
umount_all_for_device() {
  local dev="$1"
  umount_if_mounted "/target"
  umount_if_mounted "/target/boot/efi"
  umount_if_mounted "$MNT"
  umount_if_mounted "$MNT/boot/efi"
  while read -r tgt; do
    [ -n "$tgt" ] && umount_if_mounted "$tgt" || true
  done < <(findmnt -rn -S "$dev" -o TARGET | sort -r)
  udevadm settle >>"$LOGFILE" 2>&1 || true
}
bind_mount_chroot() {
  run "Bind /dev"  mount --bind /dev  "$MNT/dev"
  run "Bind /proc" mount --bind /proc "$MNT/proc"
  run "Bind /sys"  mount --bind /sys  "$MNT/sys"
  run "Bind /run"  mount --bind /run  "$MNT/run"
  mkdir -p "$MNT/sys/firmware/efi/efivars"
  mount -t efivarfs efivarfs "$MNT/sys/firmware/efi/efivars" >>"$LOGFILE" 2>&1 || true
  mkdir -p "$MNT/dev/pts"
  mount -t devpts devpts "$MNT/dev/pts" >>"$LOGFILE" 2>&1 || true
}
unbind_mount_chroot() {
  umount_if_mounted "$MNT/run"
  umount_if_mounted "$MNT/sys"
  umount_if_mounted "$MNT/proc"
  umount_if_mounted "$MNT/dev"
}

# Validate LUKS mapper name
validate_mapper_name() {
  local name="$1"
  [[ "$name" =~ ^[A-Za-z0-9._-]{1,32}$ ]] || die "Mapper name invalid. Use letters, digits, '.', '_' or '-', max 32 chars."
}

# Sizes
calc_ram_mib() { awk '/MemTotal:/ {print int(($2+1023)/1024)}' /proc/meminfo; }
parse_size_to_mib() {
  local input="$1"; local ram_mib; ram_mib="$(calc_ram_mib)"
  case "$input" in
    auto|AUTO) echo "$ram_mib" ;;
    *% ) local pct="${input%%%}"; [[ "$pct" =~ ^[0-9]+$ ]] || die "Invalid percent: $input"; echo $(( ram_mib * pct / 100 )) ;;
    *GiB|*G|*g|*Gi|*GB ) local num="${input%%[[:alpha:]]*}"; [[ "$num" =~ ^[0-9]+$ ]] || die "Invalid size: $input"; echo $(( num * 1024 )) ;;
    *MiB|*M|*m ) local num="${input%%[[:alpha:]]*}"; [[ "$num" =~ ^[0-9]+$ ]] || die "Invalid size: $input"; echo "$num" ;;
    *) [[ "$input" =~ ^[0-9]+$ ]] || die "Invalid size: $input"; echo "$input" ;;
  esac
}

# Detect ESP parent disk and partnum
detect_esp_parent() {
  local dev="$1"
  local base sys parent
  base="$(basename "$(readlink -f "$dev")")"
  sys="/sys/class/block/$base"
  if [ -r "$sys/partition" ]; then
    EFI_PARTNUM="$(cat "$sys/partition")"
    parent="$(basename "$(dirname "$(readlink -f "$sys")")")"
    EFI_DISK="/dev/$parent"
  else
    case "$dev" in
      /dev/nvme*n*p[0-9]*|/dev/mmcblk*p[0-9]*|/dev/loop*p[0-9]*)
        EFI_DISK="${dev%p[0-9]*}"
        EFI_PARTNUM="$(echo "$dev" | sed -E 's#.*p([0-9]+)$#\1#')"
        ;;
      *)
        EFI_DISK="$(echo "$dev" | sed -E 's#[0-9]+$##')"
        EFI_PARTNUM="$(echo "$dev" | sed -E 's#.*[^0-9]([0-9]+)$#\1#')"
        ;;
    esac
  fi
  [ -b "$EFI_DISK" ] || die "EFI_DISK not found for $dev"
  [ -n "$EFI_PARTNUM" ] || die "EFI_PARTNUM not found for $dev"
}

cleanup() {
  unbind_mount_chroot
  umount_if_mounted "$MNT$EFI_MNT"
  umount_if_mounted "$MNT/home"
  umount_if_mounted "$MNT/.snapshots"
  umount_if_mounted "$MNT/swap"
  umount_if_mounted "$MNT"
}
trap cleanup EXIT

# Preconditions
[ "$(id -u)" -eq 0 ] || die "Run this script as root."
[ -d /sys/firmware/efi ] || die "Live system is not in UEFI mode. Reboot in UEFI."
for c in lsblk blkid cryptsetup btrfs sed awk grep tee findmnt efibootmgr udevadm mkswap chmod chattr; do
  command -v "$c" >/dev/null 2>&1 || die "Missing command: $c"
done

step "Starting ubuntu-config ${TS}"

############################
# Planning phase (all prompts here)
############################

# 1) Detect candidate ESPs (vfat with EFI GUID) and Btrfs roots
step "Detecting candidates (ESP and Btrfs root)"
esp_candidates=()
while IFS= read -r line; do esp_candidates+=("$line"); done < <(
  lsblk -rno PATH,FSTYPE,PARTTYPE | awk '
    $2=="vfat" && tolower($3)=="c12a7328-f81f-11d2-ba4b-00a0c93ec93b" { print $1 }'
)
root_candidates=()
while IFS= read -r line; do root_candidates+=("$line"); done < <(
  lsblk -rno PATH,FSTYPE | awk '$2=="btrfs" {print $1}'
)
[ "${#esp_candidates[@]}" -ge 1 ] || die "No EFI System Partition (vfat, EFI GUID) detected."
[ "${#root_candidates[@]}" -ge 1 ] || die "No Btrfs root partition detected."

# 2) Choose ESP
ESP_DEV=""
if [ "${#esp_candidates[@]}" -gt 1 ]; then
  items=()
  for e in "${esp_candidates[@]}"; do items+=("${e}:${e}"); done
  ESP_DEV="$(ask_menu 'Select ESP' 'Multiple EFI System Partitions found:' "${items[@]}")"
else
  ESP_DEV="${esp_candidates[0]}"
  log "ESP auto-selected: ${ESP_DEV}"
fi
EFI_TYPE="$(blkid -s TYPE -o value "$ESP_DEV" || true)"
[ "$EFI_TYPE" = "vfat" ] || die "Selected ESP is not vfat: $ESP_DEV"

# 3) Choose Btrfs root
ROOT_DEV=""
if [ "${#root_candidates[@]}" -gt 1 ]; then
  items=()
  for r in "${root_candidates[@]}"; do
    # Show size hint
    sz="$(lsblk -rno SIZE "$r" | head -n1)"
    items+=("${r}:${r} (size: ${sz})")
  done
  ROOT_DEV="$(ask_menu 'Select Btrfs root' 'Multiple Btrfs partitions found:' "${items[@]}")"
else
  ROOT_DEV="${root_candidates[0]}"
  log "Root auto-selected: ${ROOT_DEV}"
fi
ROOT_TYPE="$(blkid -s TYPE -o value "$ROOT_DEV" || true)"
[ "$ROOT_TYPE" = "btrfs" ] || [ "$ROOT_TYPE" = "crypto_LUKS" ] || die "Root must be Btrfs (plain or LUKS)."

# 4) Choose LUKS mapper name
MAPPER_NAME="$(ask_input 'LUKS mapper name' 'Name for the unlocked LUKS device (letters, digits, - _ .):' 'root')"
validate_mapper_name "$MAPPER_NAME"
if [ -e "/dev/mapper/$MAPPER_NAME" ]; then
  if [ "$(ask_yes_no 'Mapper exists' "/dev/mapper/${MAPPER_NAME} exists. Close and reuse this name?" 'no')" = "yes" ]; then
    cryptsetup close "$MAPPER_NAME" || die "Could not close existing mapper $MAPPER_NAME"
  else
    alt="${MAPPER_NAME}-1"
    MAPPER_NAME="$(ask_input 'LUKS mapper name' 'Choose a different name:' "$alt")"
    validate_mapper_name "$MAPPER_NAME"
    [ -e "/dev/mapper/$MAPPER_NAME" ] && die "Mapper name still exists: ${MAPPER_NAME}"
  fi
fi

# 5) Choose swap mode (clear numeric menu with recommendation)
ram_mib="$(calc_ram_mib)"
default_swap_mode="zram"  # recommended for 8GiB and no hibernation
SWAP_MODE="$(ask_menu 'Swap mode' 'Choose swap configuration (recommend zRAM for 8GiB, no hibernation):' \
  "zram:zRAM (compressed RAM swap, fewer SSD writes) [recommended]" \
  "btrfs:Btrfs swapfile (supports hibernation)")"
[[ "$SWAP_MODE" =~ ^(btrfs|zram)$ ]] || die "Invalid swap mode: $SWAP_MODE"

# 6) Swap size and hibernation
HIBERNATE="0"
if [ "$SWAP_MODE" = "btrfs" ]; then
  SWAP_INPUT="$(ask_input 'Btrfs swap size' 'Enter size (auto, 100%, 4096MiB, 4GiB):' '100%')"
  if [ "$(ask_yes_no 'Hibernation' 'Enable hibernation (only with Btrfs swapfile)?' 'no')" = "yes" ]; then
    HIBERNATE="1"
  fi
else
  # For 8 GiB RAM, suggest 50–75% (4096–6144MiB)
  SWAP_INPUT="$(ask_input 'zRAM size' 'Enter size (auto, 50%, 4096MiB, 6144MiB):' '50%')"
  HIBERNATE="0"
fi
SWAP_MIB="$(parse_size_to_mib "$SWAP_INPUT")"

# 7) LUKS passphrase (once, confirmed)
LUKS_PASS="$(ask_password_confirm 'LUKS Passphrase' 'Enter new LUKS2 passphrase (used for conversion and opening):')"

# 8) Summary and confirmation (single prompt)
step "Execution summary"
log "- ESP partition:  ${ESP_DEV} (type: ${EFI_TYPE:-unknown})"
log "- Root partition: ${ROOT_DEV} (type: ${ROOT_TYPE:-unknown})"
log "- Mapper name:    ${MAPPER_NAME}"
log "- Swap:           ${SWAP_MODE}, size=${SWAP_MIB} MiB, hibernation=${HIBERNATE}"
printf "%b" "${C_BOLD}Proceed with changes (y/N)? ${C_RESET}" >&3
ans="$(read_line)"; [[ "$ans" =~ ^[Yy]$ ]] || die "Cancelled by user."

############################
# Execution phase (no prompts)
############################

# Release any live mounts
step "Releasing live mounts"
umount_all_for_device "$ROOT_DEV"
umount_all_for_device "$ESP_DEV"

# Convert to LUKS2 if needed
if [ "$ROOT_TYPE" != "crypto_LUKS" ]; then
  step "Prepare Btrfs layout and convert to LUKS2 (in-place)"
  mkdir -p "$MNT"
  run "Mount top-level (subvolid=5)" mount -o subvolid=5 "$ROOT_DEV" "$MNT"

  # Ensure subvolumes exist
  if ! btrfs subvolume list "$MNT" | grep -qE 'path @($|/)'; then
    run "Create top-level snapshot -> @" bash -c "cd '$MNT' && btrfs subvolume snapshot . @"
    while IFS= read -r p; do
      base="$(basename "$p")"
      [[ "$base" == @* ]] && continue
      if mountpoint -q "$p"; then
        log "(skip) mountpoint: $p"
      else
        run "Cleanup: $(basename "$p")" rm -rf "$p"
      fi
    done < <(find "$MNT" -mindepth 1 -maxdepth 1)
  else
    log "Subvolume @ already present."
  fi
  for sv in @home @snapshots; do
    if ! btrfs subvolume list "$MNT" | grep -qE "path ${sv}($|/)"; then
      run "Create subvolume ${sv}" btrfs subvolume create "$MNT/$sv"
    fi
  done
  if [ "$SWAP_MODE" = "btrfs" ]; then
    if ! btrfs subvolume list "$MNT" | grep -qE "path @swap($|/)"; then
      run "Create subvolume @swap" btrfs subvolume create "$MNT/@swap"
    fi
  fi

  # Temporary shrink for LUKS header
  SHRUNK=0
  if btrfs filesystem resize "-$KEYSLOT_SIZE" "$MNT" >>"$LOGFILE" 2>&1; then SHRUNK=1; fi
  umount_if_mounted "$MNT"
  umount_all_for_device "$ROOT_DEV"

  step "In-place LUKS2 conversion (cryptsetup reencrypt)"
  if ! printf "%s" "$LUKS_PASS" | cryptsetup reencrypt --encrypt --type luks2 --batch-mode --reduce-device-size "$KEYSLOT_SIZE" --key-file - "$ROOT_DEV" 1>&3 2>&4; then
    warn "Reencrypt failed."
    if [ "$SHRUNK" -eq 1 ]; then
      mkdir -p "$MNT"; mount -o subvolid=5 "$ROOT_DEV" "$MNT" >>"$LOGFILE" 2>&1 || true
      btrfs filesystem resize "+$KEYSLOT_SIZE" "$MNT" >>"$LOGFILE" 2>&1 || true
      umount_if_mounted "$MNT"
    fi
    die "cryptsetup reencrypt failed. Ensure the disk is not mounted anywhere."
  fi
  ok "LUKS2 conversion completed"
  ROOT_TYPE="crypto_LUKS"
else
  step "Root partition already encrypted (crypto_LUKS)"
fi

# Open LUKS
if [ ! -e "/dev/mapper/$MAPPER_NAME" ]; then
  step "Opening LUKS container -> ${MAPPER_NAME}"
  printf "%s" "$LUKS_PASS" | run "cryptsetup open" cryptsetup open --key-file - "$ROOT_DEV" "$MAPPER_NAME"
else
  log "LUKS already open: /dev/mapper/${MAPPER_NAME}"
fi
ROOT_MAPPER="/dev/mapper/$MAPPER_NAME"

# Mount subvolumes
step "Mounting subvolumes"
mkdir -p "$MNT"
run "Mount / (@)" mount -o subvol=@ "$ROOT_MAPPER" "$MNT"
mkdir -p "$MNT/home" "$MNT/.snapshots"
mount -o subvol=@home      "$ROOT_MAPPER" "$MNT/home"       >>"$LOGFILE" 2>&1 || true
mount -o subvol=@snapshots "$ROOT_MAPPER" "$MNT/.snapshots" >>"$LOGFILE" 2>&1 || true
if [ "$SWAP_MODE" = "btrfs" ]; then
  mkdir -p "$MNT/swap"
  mount -o subvol=@swap "$ROOT_MAPPER" "$MNT/swap" >>"$LOGFILE" 2>&1 || true
fi

# Swap setup
if [ "$SWAP_MODE" = "btrfs" ]; then
  step "Preparing Btrfs swapfile (${SWAP_MIB} MiB)"
  chattr +C "$MNT/swap" >>"$LOGFILE" 2>&1 || true
  run "btrfs mkswapfile" btrfs filesystem mkswapfile -s "${SWAP_MIB}m" "$MNT/swap/swapfile"
  run "mkswap" mkswap "$MNT/swap/swapfile"
  run "chmod 600 swapfile" chmod 600 "$MNT/swap/swapfile"
else
  step "zRAM selected (no on-disk @swap, hibernation disabled)"
fi

# fstab
step "Updating fstab"
BTRFS_UUID="$(blkid -s UUID -o value "$ROOT_MAPPER")"
LUKS_UUID="$(cryptsetup luksUUID "$ROOT_DEV")"
EFI_UUID="$(blkid -s UUID -o value "$ESP_DEV")"
[ -n "$BTRFS_UUID" ] || die "Btrfs UUID not found."
[ -n "$LUKS_UUID" ]  || die "LUKS UUID not found."
[ -n "$EFI_UUID" ]   || die "EFI UUID not found."

cp -a "$MNT/etc/fstab" "$MNT/etc/fstab.bak.$TS" >>"$LOGFILE" 2>&1 || true
sed -i '/[[:space:]]\/[[:space:]]\|[[:space:]]\/home[[:space:]]\|[[:space:]]\/\.snapshots[[:space:]]\|[[:space:]]\/swap[[:space:]]\|[[:space:]]\/boot\/efi[[:space:]]\|[[:space:]]\/efi[[:space:]]/d' "$MNT/etc/fstab"
cat > "$MNT/etc/fstab.new" <<EOF
UUID=$BTRFS_UUID /           btrfs defaults,subvol=@           0 1
UUID=$BTRFS_UUID /home       btrfs defaults,subvol=@home       0 2
UUID=$BTRFS_UUID /.snapshots btrfs defaults,subvol=@snapshots  0 2
UUID=$EFI_UUID  /efi         vfat  umask=0077                  0 1
EOF
if [ "$SWAP_MODE" = "btrfs" ]; then
  cat >> "$MNT/etc/fstab.new" <<'EOF'
/swap/swapfile none          swap  defaults                    0 0
EOF
fi
cat "$MNT/etc/fstab.new" >> "$MNT/etc/fstab"
rm -f "$MNT/etc/fstab.new"
ok "fstab updated"

# Mount ESP and symlink /boot/efi
step "Mount ESP at ${EFI_MNT} and symlink /boot/efi -> /efi"
mkdir -p "$MNT$EFI_MNT" "$MNT/boot"
umount_if_mounted "$MNT$EFI_MNT"
run "Mount ESP" mount -o uid=0,gid=0,fmask=0077,dmask=0077 "$ESP_DEV" "$MNT$EFI_MNT"
umount_if_mounted "$MNT/boot/efi"
[ -L "$MNT/boot/efi" ] || [ -d "$MNT/boot/efi" ] && run "Replace /boot/efi" rm -rf "$MNT/boot/efi"
ln -s "$EFI_MNT" "$MNT/boot/efi" >>"$LOGFILE" 2>&1

# Prepare chroot and detect ESP parent
step "Prepare chroot"
bind_mount_chroot
EFI_DISK=""; EFI_PARTNUM=""
detect_esp_parent "$ESP_DEV"

# Chroot: configure boot/UKI/dracut and optional zRAM
step "Boot/UKI configuration inside chroot"
chroot "$MNT" env \
  EFI_DISK="$EFI_DISK" EFI_PARTNUM="$EFI_PARTNUM" \
  LUKS_UUID="$LUKS_UUID" BTRFS_UUID="$BTRFS_UUID" \
  MAPPER_NAME="$MAPPER_NAME" TS="$TS" \
  SWAP_MODE="$SWAP_MODE" SWAP_MIB="$SWAP_MIB" HIBERNATE="$HIBERNATE" \
  /bin/bash -s <<'CHROOT_EOF'
set -Eeuo pipefail

exec 3>&1 4>&2
LOGFILE="/var/log/ubuntu-config-chroot-${TS}.log"
exec >>"$LOGFILE" 2>&1

log() { printf "%b\n" "➜ $*" >&3; }
ok()  { printf "%b\n" "✔ $*" >&3; }
warn(){ printf "%b\n" "⚠ $*" >&3; }
err() { printf "%b\n" "✖ $*" >&3; }

[ -d /sys/firmware/efi ] || { err "No UEFI in chroot"; exit 1; }
mount | grep -q '/sys/firmware/efi/efivars' || mount -t efivarfs efivarfs /sys/firmware/efi/efivars >>"$LOGFILE" 2>&1 || true

# Optional: clear NVRAM entries (kept for consistency, but can be skipped if you prefer)
if command -v efibootmgr >/dev/null 2>&1; then
  while read -r id; do efibootmgr -b "$id" -B >>"$LOGFILE" 2>&1 || true; done < <(efibootmgr | awk '/^Boot[0-9A-Fa-f]{4}/ {sub(/^Boot/,"",$1); sub(/\*.*/,"",$1); print $1}')
fi

# Clean ESP layout
rm -rf /efi/* >>"$LOGFILE" 2>&1 || true
mkdir -p /efi/EFI/systemd /efi/loader /efi/EFI/Linux

# Purge GRUB/shim
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get purge -y --allow-remove-essential \
  grub-common grub-efi-amd64 grub-efi-amd64-bin grub-efi-amd64-signed grub-efi-amd64-unsigned \
  shim-signed os-prober mokutil || true
apt-get autoremove -y || true

# Remove GRUB files from /boot
rm -rf /boot/grub /boot/grub* /boot/grubenv >>"$LOGFILE" 2>&1 || true

# Install systemd-boot + ukify + dracut
apt-get install -y systemd-boot-efi systemd-boot-tools systemd-ukify dracut efibootmgr binutils || true
if command -v bootctl >/dev/null 2>&1; then
  bootctl install >>"$LOGFILE" 2>&1 || bootctl --esp-path=/efi install >>"$LOGFILE" 2>&1 || true
  bootctl update  >>"$LOGFILE" 2>&1 || bootctl --esp-path=/efi update  >>"$LOGFILE" 2>&1 || true
fi

# zRAM (optional)
if [ "${SWAP_MODE}" = "zram" ]; then
  if apt-get install -y systemd-zram-generator >/dev/null 2>&1; then
    mkdir -p /etc/systemd
    cat > /etc/systemd/zram-generator.conf <<EOF_ZRAM
[zram0]
zram-size = ${SWAP_MIB}MiB
compression-algorithm = zstd
swap-priority = 100
fs-type = swap
EOF_ZRAM
    ok "zRAM (systemd-zram-generator) configured: ${SWAP_MIB}MiB"
  else
    warn "systemd-zram-generator not available, using zram-tools"
    apt-get install -y zram-tools || warn "zram-tools install failed"
    RAM_MIB="$(awk '/MemTotal:/ {print int(($2+1023)/1024)}' /proc/meminfo)"
    PCT=$(( SWAP_MIB * 100 / RAM_MIB )); [ "$PCT" -le 0 ] && PCT=50
    cat > /etc/default/zramswap <<EOF_ZRT
ALGO=zstd
PERCENT=${PCT}
PRIORITY=100
EOF_ZRT
    ok "zRAM (zram-tools) configured: ~${PCT}% of RAM"
  fi
fi

# Kernel cmdline (include LUKS and optional resume)
SWAPFILE="/swap/swapfile"
CMDLINE="rd.luks.name=${LUKS_UUID}=${MAPPER_NAME} root=UUID=${BTRFS_UUID} rootflags=subvol=@ splash quiet resume=/dev/mapper/${MAPPER_NAME}"
if [ "${SWAP_MODE}" = "btrfs" ] && [ "${HIBERNATE}" = "1" ] && [ -f "$SWAPFILE" ]; then
  RESUME_OFFSET="$(btrfs inspect-internal map-swapfile -r "$SWAPFILE" 2>/dev/null | tr -d '[:space:]' || true)"
  if [ -z "$RESUME_OFFSET" ]; then
    RESUME_OFFSET="$(btrfs inspect-internal map-swapfile "$SWAPFILE" 2>/dev/null | awk -F': *' '/Resume offset/ {print $2}' | tr -d '[:space:]')"
  fi
  if [ -n "$RESUME_OFFSET" ]; then CMDLINE="${CMDLINE} resume_offset=${RESUME_OFFSET}"; fi
else
  CMDLINE="$(echo "$CMDLINE" | sed 's/[[:space:]]resume=[^[:space:]]\+//g')"
fi
mkdir -p /etc/kernel
cat > /etc/kernel/install.conf <<'EOF_KI'
layout=uki
uki_generator=ukify
initrd_generator=dracut
EOF_KI
cat > /etc/kernel/uki.conf <<'EOF_UK'
[UKI]
Cmdline=@/etc/kernel/cmdline
EOF_UK
echo "${CMDLINE}" > /etc/kernel/cmdline

# Dracut modules
mkdir -p /etc/dracut.conf.d
cat > /etc/dracut.conf.d/10-ubuntu.conf <<'EOF_DRC'
hostonly="yes"
compress="zstd"
EOF_DRC
cat > /etc/dracut.conf.d/89-btrfs.conf <<'EOF_BTR'
add_dracutmodules+=" systemd btrfs "
EOF_BTR
cat > /etc/dracut.conf.d/90-luks.conf <<'EOF_LUKS'
add_dracutmodules+=" crypt "
EOF_LUKS
if [ "${SWAP_MODE}" = "btrfs" ] && [ "${HIBERNATE}" = "1" ]; then
  cat > /etc/dracut.conf.d/95-hibernate.conf <<'EOF_HIB'
add_dracutmodules+=" resume "
EOF_HIB
fi

# Generate UKI
KVER="$(uname -r)"
KIMG="/boot/vmlinuz-${KVER}"
if [ ! -f "$KIMG" ]; then
  KVER="$(ls -1 /lib/modules | sort -V | tail -n1)"
  KIMG="/boot/vmlinuz-${KVER}"
fi
[ -f "$KIMG" ] || { err "Kernel image not found: ${KIMG}"; exit 1; }
kernel-install -v add "${KVER}" "${KIMG}" >>"$LOGFILE" 2>&1 || err "kernel-install failed (see $LOGFILE)"

# Loader config and boot order
cat > /efi/loader/loader.conf <<'EOF_LD'
default @saved
timeout 0
console-mode keep
EOF_LD
if command -v efibootmgr >/dev/null 2>&1; then
  LOADER='\\EFI\\systemd\\systemd-bootx64.efi'
  if ! efibootmgr -v | grep -q "Linux Boot Manager"; then
    efibootmgr --create --disk "$EFI_DISK" --part "$EFI_PARTNUM" --loader "$LOADER" --label "Linux Boot Manager" --unicode >>"$LOGFILE" 2>&1 || true
  fi
  SDBOOT_ID="$(efibootmgr -v | awk -F"[*]" '/Linux Boot Manager/ {print $1}' | sed 's/Boot//;s/[[:space:]]//g')"
  if [ -n "$SDBOOT_ID" ]; then
    efibootmgr -n "$SDBOOT_ID" >>"$LOGFILE" 2>&1 || true
    CUR="$(efibootmgr | awk -F': ' '/BootOrder/ {print $2}')"
    NEW="$SDBOOT_ID"; for id in $(echo "$CUR" | tr ',' ' '); do [ "$id" != "$SDBOOT_ID" ] && NEW="$NEW,$id"; done
    efibootmgr -o "$NEW" >>"$LOGFILE" 2>&1 || true
  fi
fi

ok "Chroot configuration completed"
CHROOT_EOF

# Finish: unmount and close LUKS
step "Final cleanup"
cleanup
if [ -b "/dev/mapper/$MAPPER_NAME" ]; then
  run "Close LUKS" cryptsetup close "$MAPPER_NAME" || true
fi
ok "Done. Logs: ${LOGFILE}"

