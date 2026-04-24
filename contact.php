<?php
declare(strict_types=1);

session_start();

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

$config = is_file(__DIR__ . '/config.php') ? require __DIR__ . '/config.php' : [];
$recipientEmail = is_array($config) ? (string)($config['recipient_email'] ?? '') : '';
$privacyPolicyVersion = is_array($config) ? (string)($config['privacy_policy_version'] ?? 'sin versión') : 'sin versión';

$limits = [
    'name' => 80,
    'email' => 120,
    'message' => 2000,
    'user_agent' => 300,
];

function json_response(bool $success, string $message, int $statusCode = 200, array $extra = []): void
{
    http_response_code($statusCode);
    echo json_encode(array_merge([
        'success' => $success,
        'message' => $message,
    ], $extra), JSON_UNESCAPED_UNICODE);
    exit;
}

function new_csrf_token(): string
{
    $token = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $token;
    $_SESSION['csrf_used'] = false;
    return $token;
}

function clean_text(string $value, int $maxLength): string
{
    $value = trim($value);
    $value = str_replace(["\0", "\r"], '', $value);
    $value = preg_replace('/[ \t]+/', ' ', $value) ?? '';
    return function_exists('mb_substr') ? mb_substr($value, 0, $maxLength, 'UTF-8') : substr($value, 0, $maxLength);
}

function has_header_injection(string $value): bool
{
    return preg_match('/[\r\n]|%0a|%0d/i', $value) === 1;
}

function text_length(string $value): int
{
    return function_exists('mb_strlen') ? mb_strlen($value, 'UTF-8') : strlen($value);
}

function safe_mail_domain(): string
{
    $host = (string)($_SERVER['HTTP_HOST'] ?? 'localhost');
    $host = strtolower(trim(explode(':', $host)[0]));

    if (!preg_match('/^[a-z0-9.-]+$/', $host)) {
        return 'localhost';
    }

    return $host;
}

function client_ip(): string
{
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');

    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        return $ip;
    }

    return 'No disponible';
}

function too_many_requests(): bool
{
    $now = time();
    $windowSeconds = 300;
    $maxAttempts = 5;

    if (!isset($_SESSION['rate_limit']) || !is_array($_SESSION['rate_limit'])) {
        $_SESSION['rate_limit'] = [];
    }

    $_SESSION['rate_limit'] = array_values(array_filter(
        $_SESSION['rate_limit'],
        static fn ($timestamp) => is_int($timestamp) && ($now - $timestamp) < $windowSeconds
    ));

    if (count($_SESSION['rate_limit']) >= $maxAttempts) {
        return true;
    }

    $_SESSION['rate_limit'][] = $now;
    return false;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && ($_GET['action'] ?? '') === 'csrf') {
    json_response(true, 'Token generado.', 200, ['token' => new_csrf_token()]);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(false, 'Método no permitido.', 405);
}

if (too_many_requests()) {
    json_response(false, 'Has enviado demasiados intentos. Espera unos minutos e inténtalo de nuevo.', 429);
}

$postedToken = $_POST['csrf_token'] ?? '';
$sessionToken = $_SESSION['csrf_token'] ?? '';

if (
    !is_string($postedToken)
    || !is_string($sessionToken)
    || $postedToken === ''
    || $sessionToken === ''
    || !hash_equals($sessionToken, $postedToken)
    || !empty($_SESSION['csrf_used'])
) {
    json_response(false, 'La sesión del formulario ha caducado. Recarga la página e inténtalo de nuevo.', 400);
}

$_SESSION['csrf_used'] = true;

if (!empty($_POST['website'] ?? '')) {
    json_response(false, 'No se pudo enviar el mensaje.', 400);
}

$rawName = (string)($_POST['name'] ?? '');
$rawEmail = (string)($_POST['email'] ?? '');
$rawMessage = (string)($_POST['message'] ?? '');
$privacyAcceptance = (string)($_POST['privacy_acceptance'] ?? '');

if (text_length($rawName) > $limits['name'] || text_length($rawEmail) > $limits['email'] || text_length($rawMessage) > $limits['message']) {
    json_response(false, 'Uno de los campos supera la longitud permitida.', 422);
}

$name = clean_text($rawName, $limits['name']);
$email = clean_text($rawEmail, $limits['email']);
$message = clean_text($rawMessage, $limits['message']);

if ($name === '' || $email === '' || $message === '') {
    json_response(false, 'Completa todos los campos obligatorios.', 422);
}

if ($privacyAcceptance !== '1') {
    json_response(false, 'Debes aceptar la política de privacidad para enviar el mensaje.', 422);
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL) || has_header_injection($email) || has_header_injection($name)) {
    json_response(false, 'Introduce un email válido.', 422);
}

if (!filter_var($recipientEmail, FILTER_VALIDATE_EMAIL)) {
    json_response(false, 'No se pudo enviar el mensaje en este momento.', 500);
}

$safeName = htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$safeEmail = htmlspecialchars($email, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$safeMessage = htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$safeIp = htmlspecialchars(client_ip(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$safeUserAgent = htmlspecialchars(clean_text((string)($_SERVER['HTTP_USER_AGENT'] ?? 'No disponible'), $limits['user_agent']), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$safePrivacyPolicyVersion = htmlspecialchars($privacyPolicyVersion, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$acceptedAt = date('c');

$subject = 'Nuevo mensaje desde ESDLV';
$body = "Has recibido un nuevo mensaje desde la web.\n\n";
$body .= "Nombre: {$safeName}\n";
$body .= "Email: {$safeEmail}\n\n";
$body .= "Mensaje:\n{$safeMessage}\n";
$body .= "\n---\n";
$body .= "Aceptación legal: sí\n";
$body .= "Fecha de aceptación: {$acceptedAt}\n";
$body .= "Política aceptada: política de privacidad versión {$safePrivacyPolicyVersion}\n";
$body .= "IP: {$safeIp}\n";
$body .= "Navegador: {$safeUserAgent}\n";

$headers = [
    'From: ESDLV <no-reply@' . safe_mail_domain() . '>',
    'Reply-To: ' . $safeEmail,
    'Content-Type: text/plain; charset=UTF-8',
    'X-Mailer: PHP/' . phpversion(),
];

$sent = @mail($recipientEmail, $subject, $body, implode("\r\n", $headers));

if (!$sent) {
    json_response(false, 'No se pudo enviar el mensaje en este momento. Inténtalo de nuevo más tarde.', 500);
}

unset($_SESSION['csrf_token'], $_SESSION['csrf_used']);
json_response(true, 'Mensaje enviado correctamente. Gracias por escribir.');
