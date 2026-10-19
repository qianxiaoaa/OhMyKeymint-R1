<?php
/**
 * Ed25519 签名（防盗）辅助 —— 依赖 PHP sodium 扩展。
 * 首次运行会自动生成密钥对。
 */

/**
 * 确保密钥对存在，返回 [secret(b64), public(b64)]。
 */
function sign_ensure_keys(string $keysDir, string $pubOut, string $secretIn): array {
    $pubFile  = rtrim($keysDir, '/') . '/' . $pubOut;
    $secFile  = rtrim($keysDir, '/') . '/' . $secretIn;

    if (file_exists($secFile) && file_exists($pubFile)) {
        return [trim(file_get_contents($secFile)), trim(file_get_contents($pubFile))];
    }
    if (!function_exists('sodium_crypto_sign_keypair')) {
        throw new RuntimeException('缺少 sodium 扩展，无法生成签名密钥');
    }
    $kp     = sodium_crypto_sign_keypair();
    $secret = base64_encode(sodium_crypto_sign_secretkey($kp));
    $public = base64_encode(sodium_crypto_sign_publickey($kp));

    @mkdir($keysDir, 0755, true);
    file_put_contents($secFile, $secret);
    file_put_contents($pubFile, $public);

    return [$secret, $public];
}

/**
 * 签名数据，返回 base64 签名。
 */
function sign_data(string $secretB64, string $data): string {
    $secret = base64_decode($secretB64);
    return base64_encode(sodium_crypto_sign_detached($data, $secret));
}
