/**
 * 统一文本复制：优先走 Tauri 剪贴板插件（WKWebView 下不受用户手势限制），失败时依次回退到浏览器 API 与 execCommand。
 */
import { writeText as writeClipboardText } from "@tauri-apps/plugin-clipboard-manager";

/** 通过临时 readonly 文本域与 execCommand 复制文本，文本域始终在 finally 中移除。 */
async function copyViaExecCommand(text: string): Promise<void> {
  if (typeof document === "undefined") {
    throw new Error("document is unavailable");
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.top = "-9999px";
  textarea.style.left = "-9999px";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  try {
    textarea.select();
    const succeeded = document.execCommand("copy");
    if (!succeeded) {
      throw new Error("execCommand copy failed");
    }
  } finally {
    document.body.removeChild(textarea);
  }
}

/** 复制文本到系统剪贴板，逐级回退；全部失败时抛出最后一次错误由调用方处理。 */
export async function copyTextToClipboard(text: string): Promise<void> {
  let lastError: unknown;

  try {
    await writeClipboardText(text);
    return;
  } catch (error) {
    lastError = error;
  }

  try {
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return;
    }
    throw new Error("clipboard api unavailable");
  } catch (error) {
    lastError = error;
  }

  try {
    await copyViaExecCommand(text);
    return;
  } catch (error) {
    lastError = error;
  }

  throw lastError;
}
