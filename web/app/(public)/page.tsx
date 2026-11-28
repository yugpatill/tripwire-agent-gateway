import { Hero } from "@/components/playground/hero";
import { ScenarioGrid } from "@/components/playground/scenario-grid";

export default function HomePage() {
  return (
    <main className="flex flex-1 flex-col">
      <Hero />
      <ScenarioGrid />
    </main>
  );
}
