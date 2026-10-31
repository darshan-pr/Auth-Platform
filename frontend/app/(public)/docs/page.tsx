import type { Metadata } from "next";
import { DocsPage } from "../../../components/docs-page";

export const instant = false;

export const metadata: Metadata = { title: "Documentation" };

export default function DocsRoute() {
  return <DocsPage />;
}
