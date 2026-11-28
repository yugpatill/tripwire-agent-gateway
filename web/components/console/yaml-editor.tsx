"use client";

// Client only: loaded with next/dynamic { ssr: false } (Monaco touches `window`).
import Editor, { loader, type OnMount } from "@monaco-editor/react";
import * as monaco from "monaco-editor/esm/vs/editor/editor.api.js";
import "monaco-editor/esm/vs/basic-languages/yaml/yaml.contribution.js";
import { configureMonacoYaml } from "monaco-yaml";
import { useEffect, useRef } from "react";

import type { PolicyErrorItem } from "@/lib/console/api";

// Bundle Monaco instead of loading it from a CDN, and give it local workers.
window.MonacoEnvironment = {
  getWorker(_id: string, label: string) {
    if (label === "yaml") return new Worker(new URL("monaco-yaml/yaml.worker", import.meta.url), { type: "module" });
    return new Worker(new URL("monaco-editor/esm/vs/editor/editor.worker.js", import.meta.url), { type: "module" });
  },
};
loader.config({ monaco });

const MODEL_URI = "file:///tripwire/policy.yaml";
let yamlConfigured: ReturnType<typeof configureMonacoYaml> | null = null;

export interface YamlEditorProps {
  value: string;
  onChange: (v: string) => void;
  schema: Record<string, unknown> | null;
  serverErrors: PolicyErrorItem[];
  readOnly: boolean;
  dark: boolean;
  onReady?: (reveal: (line: number, column: number) => void) => void;
}

export default function YamlEditor({ value, onChange, schema, serverErrors, readOnly, dark, onReady }: YamlEditorProps) {
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null);

  useEffect(() => {
    if (!schema) return;
    const options: Parameters<typeof configureMonacoYaml>[1] = {
      enableSchemaRequest: false,
      validate: true,
      completion: true,
      hover: true,
      schemas: [{ uri: "https://tripwire.local/policy.schema.json", fileMatch: [MODEL_URI], schema }],
    };
    if (yamlConfigured) yamlConfigured.update(options);
    else yamlConfigured = configureMonacoYaml(monaco, options);
  }, [schema]);

  useEffect(() => {
    const model = editorRef.current?.getModel();
    if (!model) return;
    monaco.editor.setModelMarkers(
      model,
      "tripwire",
      serverErrors.map((e) => {
        const line = Math.min(Math.max(e.line ?? 1, 1), model.getLineCount());
        return {
          severity: monaco.MarkerSeverity.Error,
          message: `${e.loc}: ${e.message}`,
          startLineNumber: line,
          startColumn: e.column ?? 1,
          endLineNumber: line,
          endColumn: model.getLineMaxColumn(line),
        };
      }),
    );
  }, [serverErrors]);

  const onMount: OnMount = (editor) => {
    editorRef.current = editor;
    onReady?.((line, column) => {
      editor.revealLineInCenter(line);
      editor.setPosition({ lineNumber: line, column });
      editor.focus();
    });
  };

  return (
    <Editor
      height="100%"
      language="yaml"
      path={MODEL_URI}
      value={value}
      theme={dark ? "vs-dark" : "vs"}
      onChange={(v) => onChange(v ?? "")}
      onMount={onMount}
      loading={<div className="text-muted-foreground p-4 text-sm">Loading editor…</div>}
      options={{
        readOnly,
        minimap: { enabled: false },
        fontSize: 13,
        tabSize: 2,
        scrollBeyondLastLine: false,
        automaticLayout: true,
        wordWrap: "on",
        ariaLabel: "Policy YAML",
      }}
    />
  );
}
