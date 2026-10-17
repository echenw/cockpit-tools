import assert from "node:assert/strict";
import test from "node:test";
import { copyTextToClipboard } from "./clipboard.ts";

interface FakeTextarea {
  tagName: string;
  value: string;
  style: Record<string, string>;
  attributes: Record<string, string>;
  selected: boolean;
  setAttribute: (name: string, value: string) => void;
  select: () => void;
}

function installDocumentStub(execCommand: () => boolean) {
  const state = {
    execCommandCalls: 0,
    appended: 0,
    removed: 0,
    createdTextareas: [] as FakeTextarea[],
  };
  const previousDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  const body = {
    appendChild(node: unknown) {
      state.appended += 1;
      return node;
    },
    removeChild(node: unknown) {
      state.removed += 1;
      return node;
    },
  };
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    writable: true,
    value: {
      body,
      createElement(tag: string) {
        const element: FakeTextarea = {
          tagName: tag,
          value: "",
          style: {},
          attributes: {},
          selected: false,
          setAttribute(name: string, value: string) {
            this.attributes[name] = value;
          },
          select() {
            this.selected = true;
          },
        };
        state.createdTextareas.push(element);
        return element;
      },
      execCommand(command: string) {
        void command;
        state.execCommandCalls += 1;
        return execCommand();
      },
    },
  });
  return {
    state,
    restore() {
      if (previousDocument) {
        Object.defineProperty(globalThis, "document", previousDocument);
      } else {
        delete (globalThis as { document?: unknown }).document;
      }
    },
  };
}

function installNavigatorStub(
  writeText: ((text: string) => Promise<void>) | undefined,
) {
  const previousNavigator = Object.getOwnPropertyDescriptor(
    globalThis,
    "navigator",
  );
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    writable: true,
    value: writeText ? { clipboard: { writeText } } : undefined,
  });
  return {
    restore() {
      if (previousNavigator) {
        Object.defineProperty(globalThis, "navigator", previousNavigator);
      } else {
        delete (globalThis as { navigator?: unknown }).navigator;
      }
    },
  };
}

test("uses the browser clipboard when the Tauri plugin is unavailable", async () => {
  const calls: string[] = [];
  const navigatorStub = installNavigatorStub(async (text) => {
    calls.push(text);
  });
  const documentStub = installDocumentStub(() => true);
  try {
    await copyTextToClipboard("hello");
    assert.deepEqual(calls, ["hello"]);
    assert.equal(documentStub.state.execCommandCalls, 0);
  } finally {
    documentStub.restore();
    navigatorStub.restore();
  }
});

test("falls back to execCommand when the browser clipboard is denied", async () => {
  const notAllowedError = new Error("The request is not allowed");
  notAllowedError.name = "NotAllowedError";
  const navigatorStub = installNavigatorStub(async () => {
    throw notAllowedError;
  });
  const documentStub = installDocumentStub(() => true);
  try {
    await copyTextToClipboard("hello");
    assert.equal(documentStub.state.execCommandCalls, 1);
    assert.equal(documentStub.state.appended, 1);
    assert.equal(documentStub.state.removed, 1);
    assert.equal(documentStub.state.createdTextareas[0].value, "hello");
    assert.equal(documentStub.state.createdTextareas[0].selected, true);
  } finally {
    documentStub.restore();
    navigatorStub.restore();
  }
});

test("rejects when the plugin, browser clipboard and execCommand all fail", async () => {
  const navigatorStub = installNavigatorStub(undefined);
  const documentStub = installDocumentStub(() => false);
  try {
    await assert.rejects(copyTextToClipboard("hello"));
    assert.equal(documentStub.state.execCommandCalls, 1);
    assert.equal(documentStub.state.removed, 1);
  } finally {
    documentStub.restore();
    navigatorStub.restore();
  }
});

test("rejects when execCommand throws", async () => {
  const navigatorStub = installNavigatorStub(async () => {
    throw new Error("clipboard denied");
  });
  const documentStub = installDocumentStub(() => {
    throw new Error("copy blocked");
  });
  try {
    await assert.rejects(copyTextToClipboard("hello"), /copy blocked/);
    assert.equal(documentStub.state.removed, 1);
  } finally {
    documentStub.restore();
    navigatorStub.restore();
  }
});
