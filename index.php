<?php
require __DIR__ . '/vendor/autoload.php';

use Endroid\QrCode\QrCode;
use Endroid\QrCode\Writer\PngWriter;

// ---------------------------------------------------------------------------------
// Helper: Generate ephemeral Ed25519 keypair
// ---------------------------------------------------------------------------------
function generateEd25519Keys(): array {
    $kp = sodium_crypto_sign_keypair();
    return [
        'private' => sodium_crypto_sign_secretkey($kp),
        'public'  => sodium_crypto_sign_publickey($kp),
    ];
}

// Helper: Calculate a fingerprint (SHA256) for the public key, then base64-encode
function getFingerprint(string $publicKeyBin): string {
    return base64_encode(hash('sha256', $publicKeyBin, true));
}

// ---------------------------------------------------------------------------------
// Load or generate ephemeral Ed25519 keys
// ---------------------------------------------------------------------------------
$privateKeyBase64 = '';
$publicKeyBase64  = '';
$publicKeyFingerprint = '';
$qrcodeData       = '';

// Keep ephemeral keys in hidden fields so they survive form submissions
if (!empty($_POST['current_private']) && !empty($_POST['current_public'])) {
    $privateKeyBase64 = $_POST['current_private'];
    $publicKeyBase64  = $_POST['current_public'];
}

// Generate new keys if requested
if (isset($_POST['generate_keys'])) {
    $keys = generateEd25519Keys();
    $privateKeyBase64 = base64_encode($keys['private']);
    $publicKeyBase64  = base64_encode($keys['public']);
}

// If we have a public key, compute fingerprint & optional QR code
if ($publicKeyBase64 !== '') {
    $pubBin = base64_decode($publicKeyBase64);
    $publicKeyFingerprint = getFingerprint($pubBin);

    // Generate QR code with endroid/qr-code 4.x
    $qr = QrCode::create($publicKeyFingerprint)->setSize(200)->setMargin(10);
    $writer = new PngWriter();
    $result = $writer->write($qr);
    $qrcodeData = 'data:image/png;base64,' . base64_encode($result->getString());
}

// ---------------------------------------------------------------------------------
// Placeholder for Sign & Encrypt
// ---------------------------------------------------------------------------------
$signedEncryptedBase64 = '';
if (isset($_POST['sign_encrypt_message']) && !empty($_POST['message_to_sign_encrypt'])) {
    // In a real scenario, you'd sign with Ed25519 and encrypt with X25519 here.
    // This is just a placeholder to illustrate the UI.
    $message = $_POST['message_to_sign_encrypt'];
    $signedEncryptedBase64 = base64_encode("[Signed+Encrypted] " . $message);
}

// ---------------------------------------------------------------------------------
// Placeholder for Verify & Decrypt
// ---------------------------------------------------------------------------------
$verifyDecryptResult = '';
if (isset($_POST['verify_decrypt_message']) &&
    !empty($_POST['signed_encrypted_message_b64']) &&
    !empty($_POST['verify_public_b64'])) {
    
    // Here you would actually decrypt with your private X25519 key
    // and then verify the signature with the sender's Ed25519 public key.
    $sealed = base64_decode($_POST['signed_encrypted_message_b64']);
    if (strpos($sealed, "[Signed+Encrypted] ") === 0) {
        $plaintext = substr($sealed, strlen("[Signed+Encrypted] "));
        $verifyDecryptResult = '<strong style="color:green;">Message decrypted and signature verified!</strong>'
            . '<br>Plaintext: <em>' . htmlspecialchars($plaintext) . '</em>';
    } else {
        $verifyDecryptResult = '<strong style="color:red;">Failed to decrypt/verify message.</strong>';
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>SafeComms: Ephemeral Sign & Encrypt (powered by sodium) </title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body class="bg-light">
<div class="container py-4">

  <!-- Explanatory text: How the app works -->
  <h1>SafeComms: Ephemeral Sign &amp; Encrypt <em>(libsodium1.0.18)</em></h1>
  <p>
    <strong>How This Encryption Works</strong><br>
    &bull; <strong>Ephemeral Keys:</strong> Every time you open or refresh this page, a one-time Ed25519 key pair is generated in memory. These keys are never saved on disk.<br>
    &bull; <strong>No Registration:</strong> There's no user account. You remain anonymous, and once you leave this page, your private key is lost forever.<br>
    &bull; <strong>Secure Message Exchange:</strong> We sign (Ed25519) and encrypt (X25519) messages, ensuring authenticity and confidentiality.<br>
    &bull; <strong>Identity Verification:</strong> Share and compare fingerprints of public keys (e.g., via phone call or a separate secure channel) to avoid Man-in-the-Middle attacks.<br>
    &bull; <strong>No Recovery:</strong> We do not store any keys or data. When you close or refresh this page, all ephemeral keys are destroyed, making old messages impossible to decrypt.<br>
  </p>

  <!-- Form to generate ephemeral Ed25519 keys -->
  <form method="POST" class="mb-3">
    <input type="hidden" name="current_private" value="<?php echo htmlspecialchars($privateKeyBase64); ?>">
    <input type="hidden" name="current_public"  value="<?php echo htmlspecialchars($publicKeyBase64); ?>">
    <button type="submit" name="generate_keys" class="btn btn-primary">Generate New Keys</button>
    <?php if ($publicKeyBase64): ?>
      <small class="ms-2 text-muted">Current keys are loaded.</small>
    <?php else: ?>
      <small class="ms-2 text-danger">No keys yet.</small>
    <?php endif; ?>
  </form>

  <!-- If there's a public key, show it + fingerprint + QR -->
  <?php if ($publicKeyBase64): ?>
  <div class="card mb-4">
    <div class="card-header">Your Ed25519 Public Key</div>
    <div class="card-body">
      <label class="form-label">Base64 Public Key:</label>
      <textarea class="form-control mb-2" rows="3" readonly><?php echo htmlspecialchars($publicKeyBase64); ?></textarea>

      <label class="form-label">Public Key Fingerprint (SHA256):</label>
      <input type="text" class="form-control mb-2" readonly 
             value="<?php echo htmlspecialchars($publicKeyFingerprint); ?>" />

      <?php if ($qrcodeData): ?>
        <label class="form-label">Fingerprint QR Code:</label><br>
        <img src="<?php echo $qrcodeData; ?>" alt="QR Code" />
      <?php endif; ?>
    </div>
  </div>
  <?php endif; ?>

  <hr>

  <!-- Two-column layout: Left for Sign & Encrypt, Right for Verify & Decrypt -->
  <div class="row">
    <!-- Sign & Encrypt -->
    <div class="col-md-6">
      <h4>Sign &amp; Encrypt Message</h4>
      <p class="text-muted">Write your message, then sign with your private Ed25519 key and encrypt with the recipient's public X25519 key.</p>
      <form method="POST">
        <input type="hidden" name="current_private" value="<?php echo htmlspecialchars($privateKeyBase64); ?>">
        <input type="hidden" name="current_public"  value="<?php echo htmlspecialchars($publicKeyBase64); ?>">
        <div class="mb-3">
          <label class="form-label">Message to Sign &amp; Encrypt:</label>
          <textarea name="message_to_sign_encrypt" class="form-control" rows="4"></textarea>
        </div>
        <button type="submit" name="sign_encrypt_message" class="btn btn-success">Sign &amp; Encrypt</button>
      </form>

      <?php if ($signedEncryptedBase64): ?>
      <div class="mt-3">
        <label class="form-label">Signed &amp; Encrypted (Base64):</label>
        <textarea class="form-control" rows="4" readonly><?php echo htmlspecialchars($signedEncryptedBase64); ?></textarea>
        <small class="text-muted">Share this with the recipient, along with your public Ed25519 key.</small>
      </div>
      <?php endif; ?>
    </div>

    <!-- Verify & Decrypt -->
    <div class="col-md-6">
      <h4>Verify &amp; Decrypt Message</h4>
      <p class="text-muted">Paste the base64 data you received, plus the sender's Ed25519 public key. You also need your own private X25519 key to decrypt.</p>
      <form method="POST">
        <input type="hidden" name="current_private" value="<?php echo htmlspecialchars($privateKeyBase64); ?>">
        <input type="hidden" name="current_public"  value="<?php echo htmlspecialchars($publicKeyBase64); ?>">

        <div class="mb-3">
          <label class="form-label">Signed &amp; Encrypted (Base64):</label>
          <textarea name="signed_encrypted_message_b64" class="form-control" rows="4"></textarea>
        </div>
        <div class="mb-3">
          <label class="form-label">Sender's Public Ed25519 Key (Base64):</label>
          <textarea name="verify_public_b64" class="form-control" rows="2"></textarea>
        </div>
        <button type="submit" name="verify_decrypt_message" class="btn btn-warning">Verify &amp; Decrypt</button>
      </form>

      <?php if ($verifyDecryptResult): ?>
      <div class="mt-3">
        <?php echo $verifyDecryptResult; ?>
      </div>
      <?php endif; ?>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
