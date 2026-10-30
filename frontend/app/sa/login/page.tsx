import type { Metadata } from "next";
import { LoginPage } from "../../../components/login-page";

export const metadata: Metadata = { title: "SA sign in" };

export default function SaLoginRoute() {
  return <LoginPage sa />;
}
