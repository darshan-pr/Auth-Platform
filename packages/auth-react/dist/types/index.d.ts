import { AuthClient, type AuthUser, type MessageResponse, type SignupResponse, type SessionSnapshot } from "@authplatform/auth-core";
import { type ReactNode } from "react";
export interface Appearance {
    variables?: Partial<Record<"primaryColor" | "textColor" | "backgroundColor" | "borderColor" | "radius", string>>;
    elements?: Partial<Record<"card" | "button" | "input" | "error", string>>;
}
export interface AuthProviderProps {
    children: ReactNode;
    client?: AuthClient;
    appearance?: Appearance;
    applicationName?: string;
    applicationIconUrl?: string;
    brandingRefreshIntervalMs?: number;
    checkSessionOnLoad?: boolean;
}
export interface AuthContextValue {
    client: AuthClient;
    snapshot: SessionSnapshot;
    user: AuthUser | null;
    isLoaded: boolean;
    isSignedIn: boolean;
    signIn: AuthClient["signIn"];
    verifyOtp: AuthClient["verifyOtp"];
    resendLoginOtp: AuthClient["resendLoginOtp"];
    cancelChallenge: () => void;
    signUp: AuthClient["signUp"];
    signOut: () => Promise<void>;
    retrySession: () => Promise<void>;
    refresh: () => Promise<void>;
}
export declare function AuthProvider({ children, client, appearance, applicationName, applicationIconUrl, brandingRefreshIntervalMs, checkSessionOnLoad }: AuthProviderProps): import("react").JSX.Element;
export declare function useAuth(): AuthContextValue;
export declare function useUser(): {
    isLoaded: boolean;
    isSignedIn: boolean;
    user: AuthUser | null;
};
export declare function useSession(): {
    isLoaded: boolean;
    isSignedIn: boolean;
    session: SessionSnapshot;
};
export declare function SignIn({ onSuccess }?: {
    onSuccess?: () => void;
}): import("react").JSX.Element;
export declare function SignUp({ onSuccess }?: {
    onSuccess?: (response: SignupResponse) => void;
}): import("react").JSX.Element;
export declare function VerifyEmail({ token }: {
    token: string;
}): import("react").JSX.Element;
export declare function ForgotPassword({ onSuccess, onBack }?: {
    onSuccess?: (response: MessageResponse) => void;
    onBack?: () => void;
}): import("react").JSX.Element;
export declare function UserButton(): import("react").JSX.Element;
