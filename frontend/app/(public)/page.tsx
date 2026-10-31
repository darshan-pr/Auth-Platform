import type { Metadata } from "next";
import { LandingPage } from "../../components/landing-page";

export const instant = false;

export const metadata: Metadata = {
  title: { absolute: "Auth Platform | Authentication for the applications you build" },
  description:
    "Sign-up, sign-in, email verification, one-time-password MFA, session management and roles and permissions as a hosted service.",
};

export default function HomePage() {
  return <LandingPage />;
}
