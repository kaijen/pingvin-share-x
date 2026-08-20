import { ModalsContextProps } from "@mantine/modals/lib/context";
import shareService from "../../services/share.service";
import toast from "../../utils/toast.util";
import showEnterPasswordModal from "./showEnterPasswordModal";

let pendingRequest: Promise<void> | null = null;

/**
 * The encryption key of a share is never stored on the server. The client gets it
 * wrapped in a cookie when the share is created or unlocked. If that cookie is gone,
 * the password has to be entered again to get a new one.
 */
const requestEncryptionKey = (modals: ModalsContextProps, shareId: string) => {
  // Parallel uploads can run into this at the same time, only ask once
  pendingRequest ??= new Promise<void>((resolve) => {
    showEnterPasswordModal(modals, async (password) => {
      try {
        await shareService.getShareToken(shareId, password);
        modals.closeAll();
        pendingRequest = null;
        resolve();
      } catch (e) {
        toast.axiosError(e);
      }
    });
  });

  return pendingRequest;
};

export default requestEncryptionKey;
