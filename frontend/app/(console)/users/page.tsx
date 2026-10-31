import { Suspense } from "react";
import { UsersPage } from "../../../components/users-page";

export default function UsersRoute() {
  return <Suspense fallback={null}><UsersPage /></Suspense>;
}
