import { Bot, Cpu } from "lucide-react";

import { Badge } from "@/components/ui/badge";

/** "Simulated agent" for scripted runs; "Live: <model>" for real-model runs. */
export function ModelBadge({ source }: { source?: string }) {
  if (!source) return null;
  if (source === "scripted") {
    return (
      <Badge variant="outline" title="A scripted agent that follows every injection. No language model was called.">
        <Bot aria-hidden /> Simulated agent
      </Badge>
    );
  }
  return (
    <Badge variant="outline" title="A real language model ran this agent.">
      <Cpu aria-hidden /> {source.replace(/^live: /, "Live: ")}
    </Badge>
  );
}
