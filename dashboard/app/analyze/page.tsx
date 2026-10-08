import { redirect } from "next/navigation";

// "New Analysis" was replaced by the Architecture Builder; its two demos are now
// the builder's "Load example" buttons.
export default function AnalyzeRedirect() {
  redirect("/builder");
}
