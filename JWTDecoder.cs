// JWTDecoder.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

class JWTDecoder
{
    private string token;
    private string key;
    private JObject header;
    private JObject payload;
    private string signature;
    private bool? validSignature;
    private bool? expired;

    public JWTDecoder(string token, string key)
    {
        this.token = token;
        this.key = key;
    }

    public void Decode()
    {
        var parts = token.Split('.');
        if (parts.Length != 3) throw new ArgumentException("Invalid JWT format");

        // Decode header
        var headerJson = Encoding.UTF8.GetString(Convert.FromBase64String(PadBase64(parts[0])));
        header = JObject.Parse(headerJson);

        // Decode payload
        var payloadJson = Encoding.UTF8.GetString(Convert.FromBase64String(PadBase64(parts[1])));
        payload = JObject.Parse(payloadJson);

        signature = parts[2];

        // Check exp
        if (payload.ContainsKey("exp"))
        {
            long exp = payload.Value<long>("exp");
            expired = DateTimeOffset.UtcNow.ToUnixTimeSeconds() > exp;
        }

        // Verify signature
        if (!string.IsNullOrEmpty(key))
        {
            validSignature = VerifySignature(parts);
        }
    }

    private string PadBase64(string base64)
    {
        int padLength = (4 - base64.Length % 4) % 4;
        return base64 + new string('=', padLength);
    }

    private bool VerifySignature(string[] parts)
    {
        var data = parts[0] + "." + parts[1];
        using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
        {
            var sigBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
            var sigB64 = Convert.ToBase64String(sigBytes)
                .Replace('+', '-').Replace('/', '_').TrimEnd('=');
            return sigB64 == parts[2];
        }
    }

    public Dictionary<string, object> ToDict()
    {
        var dict = new Dictionary<string, object>
        {
            ["header"] = header,
            ["payload"] = payload,
            ["signature"] = signature,
            ["token"] = token
        };
        if (validSignature.HasValue) dict["valid_signature"] = validSignature.Value;
        if (expired.HasValue) dict["expired"] = expired.Value;
        return dict;
    }

    public void Print(bool color)
    {
        Console.WriteLine("Header:");
        Console.WriteLine(header.ToString(Formatting.Indented));
        Console.WriteLine("Payload:");
        Console.WriteLine(payload.ToString(Formatting.Indented));
        if (expired.HasValue)
        {
            Console.WriteLine($"  Token {(expired.Value ? "expired" : "valid")}");
        }
        if (validSignature.HasValue)
        {
            Console.WriteLine($"  Signature {(validSignature.Value ? "verified" : "invalid")}");
        }
        Console.WriteLine($"Signature: {signature}");
    }

    static void Main(string[] args)
    {
        string token = null, key = null, file = null;
        bool jsonOut = false, color = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--key": key = args[++i]; break;
                case "--file": file = args[++i]; break;
                case "--json": jsonOut = true; break;
                case "--color": color = true; break;
                default: if (token == null) token = args[i]; break;
            }
        }

        if (file != null)
        {
            token = File.ReadAllText(file).Trim();
        }
        if (token == null)
        {
            // stdin
            if (Console.IsInputRedirected)
            {
                token = Console.In.ReadToEnd().Trim();
            }
            else
            {
                Console.Error.WriteLine("Error: no token provided");
                Environment.Exit(1);
            }
        }

        var decoder = new JWTDecoder(token, key);
        try { decoder.Decode(); }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            Environment.Exit(1);
        }

        if (jsonOut)
        {
            Console.WriteLine(JsonConvert.SerializeObject(decoder.ToDict(), Formatting.Indented));
        }
        else
        {
            decoder.Print(color || Console.IsOutputRedirected == false);
        }
    }
}
