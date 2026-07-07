-- Seed a default admin user (email: admin, password: admin)
INSERT INTO auth.users (email, password_hash, email_verified, status)
VALUES ('consultprompts@gmail.com', crypt('password123', gen_salt('bf', 10)), true, 'active')
ON CONFLICT (email) DO NOTHING;

INSERT INTO auth.user_roles (user_id, role_id)
SELECT u.id, r.id
FROM auth.users u
JOIN auth.roles r ON r.name = 'admin'
WHERE u.email = 'consultprompts@gmail.com'
ON CONFLICT DO NOTHING;
