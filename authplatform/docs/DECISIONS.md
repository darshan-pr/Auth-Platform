# Decisions

- The attached `Plan.md` is the implementation source of truth; `authplatform.md` is treated as interview documentation because its Python/OAuth/passkey scope conflicts with the explicit Stage 1 plan.
- Spring Boot 3.5.16 is used because it is the latest stable 3.x release available when this project was built. Nginx is deferred as requested.
- SDK access and refresh tokens are returned in JSON and accepted by the SDK client. Console and SA access and refresh tokens use HttpOnly, SameSite=Strict cookies because the consoles are same-site; a customer's SDK cannot reliably use an authplatform-domain cookie.
- Email delivery is asynchronous through SMTP. Local verification and reset messages are available in Mailpit rather than exposing token values from the API.
