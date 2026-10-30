# Auth platform console

This is the Next.js administration console for Auth platform.

## Getting Started

Set `NEXT_PUBLIC_API_URL` when the backend is not running at `http://localhost:8080`, then run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000/login](http://localhost:3000/login) for regular console access.

Regular console accounts use `/login`; SA access uses `/sa/login`. New console users can register at `/signup`.

Both sign-in screens support resending the email OTP and resetting a password with an email OTP. The console signup confirmation also lets users resend the verification email.

The console uses readable routes:

- `/overview`
- `/console/overview`
- `/console/apps` and `/console/apps/:id`
- `/console/account`
- `/accounts` and `/accounts/:id`
- `/apps` and `/apps/:id`
- `/users`
- `/audit-logs`

On an application's **Configuration** tab, the Application icon panel accepts PNG, JPEG, or WebP uploads (up to 5 MB) or HTTPS image URLs. It provides a crop/position preview and stores the selected icon and crop settings with the application. The saved icon appears beside the application detail heading and as that detail page's browser tab icon.

The backend API URL is configured through `NEXT_PUBLIC_API_URL`.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.

## API Routes

This directory contains example API routes for the headless API app.

For more details, see [route.js file convention](https://nextjs.org/docs/app/api-reference/file-conventions/route).
