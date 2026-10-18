#!/system/bin/sh

# KernelSU runs this script before removing the module directory. Keep the
# cleanup limited to OMK's two persistent roots; disabling a module must not
# remove data.
case "${KSU:-}" in
  true|1) ;;
  *) exit 0 ;;
esac

# Release the Qualcomm Soter service name before removing the module. The
# watchdog restores vendor.soter when disabled; this is best-effort because the
# data tree is removed below even if the service was already gone.
MODDIR=${0%/*}
if [ -x "$MODDIR/soterta.sh" ]; then
  "$MODDIR/soterta.sh" disable >/dev/null 2>&1 || true
fi
pkill -9 -f 'soterta?-svc --mode=' 2>/dev/null || true

remove_omk_directory() {
  target="$1"
  case "$target" in
    /data/adb/omk|/data/misc/keystore/omk) ;;
    *)
      echo "[oh_my_keymint] refusing unexpected cleanup path: $target" >&2
      return 1
      ;;
  esac

  if [ -e "$target" ] || [ -L "$target" ]; then
    if ! rm -rf "$target"; then
      echo "[oh_my_keymint] failed to remove $target" >&2
      return 1
    fi
  fi
}

status=0
remove_omk_directory /data/adb/omk || status=1
remove_omk_directory /data/misc/keystore/omk || status=1
exit "$status"
