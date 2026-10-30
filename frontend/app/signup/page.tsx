import type { Metadata } from "next";
import { SignupPage } from "../../components/signup-page";

export const metadata: Metadata = { title: "Create account" };

export default function SignupRoute() {
  return <SignupPage />;
}
