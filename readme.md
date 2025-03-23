<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Crypofolder</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 20px auto;
            padding: 20px;
            background-color: #f4f4f4;
        }
        h1, h2 {
            color: #333;
        }
        code {
            background: #eee;
            padding: 2px 5px;
            border-radius: 4px;
        }
        pre {
            background: #222;
            color: #fff;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <h1>Secure File Encryption</h1>

    <h2>How It Works</h2>
    <p>This encryption system ensures robust security for your files using <strong>AES-256 in CBC mode</strong>, one of the most trusted encryption standards available.</p>

    <h2>Key Features</h2>
    <ul>
        <li><strong>Strong Encryption:</strong> Each file is encrypted using <code>AES-256</code> in <code>CBC mode</code> for enhanced security.</li>
        <li><strong>Unique Encryption for Each File:</strong> A random <code>Initialization Vector (IV)</code> ensures uniqueness even if the same file is encrypted multiple times.</li>
        <li><strong>Secure Key Derivation:</strong> A random <code>salt</code> is used to derive the encryption key using <code>PBKDF2</code> to resist brute-force attacks.</li>
        <li><strong>Storage of Encryption Parameters:</strong> The salt is securely stored in <code>encryption_key.json</code>.</li>
        <li><strong>File Management:</strong>
            <ul>
                <li>Encrypted files have a <code>.enc</code> extension.</li>
                <li>Original files are securely deleted after encryption.</li>
            </ul>
        </li>
    </ul>

    <h2>Important Considerations</h2>
    <p>While this implementation provides strong security, consider the following for handling highly sensitive data:</p>
    <ul>
        <li><strong>Error Handling:</strong> Implement proper exception handling to avoid encryption failures.</li>
        <li><strong>Secure Key Storage:</strong> Use a <code>hardware security module (HSM)</code> or a secure vault instead of local storage.</li>
        <li><strong>Metadata Protection:</strong> Encrypt filenames and metadata to prevent leaks.</li>
    </ul>

    <h2>Disclaimer</h2>
    <p>This encryption tool is a basic implementation. <strong>Use it at your own risk</strong> and consider additional security measures if dealing with classified information.</p>

    <hr>
    <p>Stay secure, encrypt wisely!</p>
</body>
</html>