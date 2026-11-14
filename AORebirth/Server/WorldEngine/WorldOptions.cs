namespace WorldEngine
{
    using System;
    using System.Globalization;
    using System.Net;
    using System.Security.Cryptography.X509Certificates;

    using AORebirth.World.Contracts;

    using Utility.Config;

    public sealed class WorldOptions
    {
        public const string CertificatePathVariable = "AO_REBIRTH_WORLD_CERTIFICATE_PATH";

        public const string CertificatePasswordVariable = "AO_REBIRTH_WORLD_CERTIFICATE_PASSWORD";

        /// <summary>NPC instance ids: slot 0 keeps the single-engine range, each further slot gets its own block.</summary>
        public const int NpcIdBase = 1_000_000;

        public const int NpcIdStride = 0x00800000;

        public required IPAddress ListenAddress { get; init; }

        public required int Port { get; init; }

        /// <summary>0 when the status page is off.</summary>
        public required int StatusPort { get; init; }

        public IPAddress StatusAddress => ListenAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? IPAddress.IPv6Loopback
            : IPAddress.Loopback;

        public required TimeSpan LeaseTtl { get; init; }

        public required TimeSpan LeaseGrace { get; init; }

        public required TimeSpan Heartbeat { get; init; }

        /// <summary>How long an issued zone ticket stays claimable.</summary>
        public required TimeSpan HandoffLifetime { get; init; }

        public required string Token { get; init; }

        public X509Certificate2? ServerCertificate { get; init; }

        public bool UseTls => ServerCertificate != null;

        /// <summary>After a restart, only re-registrations are served for this long; then World is authoritative.</summary>
        public TimeSpan RecoveryWindow => LeaseTtl + LeaseGrace;

        /// <summary>An instance silent this long has lost everything it owned.</summary>
        public TimeSpan InstanceExpiry => LeaseTtl + LeaseGrace;

        public static WorldOptions FromConfig(Config? config)
        {
            WorldSettings? settings = config?.World;
            string listen = WorldSettings.ResolveListenIP(settings);
            if (!IPAddress.TryParse(listen, out IPAddress? address))
                throw new InvalidOperationException("World ListenIP must be an IP address.");
            int port = WorldSettings.ResolvePort(settings);
            int status = WorldSettings.ResolveStatusPort(settings);
            if (port > 65535 || status > 65535)
                throw new InvalidOperationException("World ports must be between 1 and 65535.");
            Uri worldUrl = ResolveWorldUrl(settings);
            bool loopback = IPAddress.IsLoopback(address);
            if (worldUrl.Scheme == Uri.UriSchemeHttp && !IsLoopback(worldUrl))
                throw new InvalidOperationException("A non-loopback World Url must use HTTPS.");
            if (!loopback && worldUrl.Scheme != Uri.UriSchemeHttps)
                throw new InvalidOperationException("A non-loopback World listener must use an HTTPS World Url.");
            string token = Environment.GetEnvironmentVariable(WorldChannel.TokenVariable) ?? string.Empty;
            if (token.Length == 0 && !loopback)
                throw new InvalidOperationException(
                    "World listens on " + listen + " but " + WorldChannel.TokenVariable + " is not set; a non-loopback World needs a token.");
            X509Certificate2? certificate = worldUrl.Scheme == Uri.UriSchemeHttps ? LoadServerCertificate() : null;

            return new WorldOptions
            {
                ListenAddress = address,
                Port = port,
                StatusPort = status < 0 ? 0 : status,
                LeaseTtl = TimeSpan.FromSeconds(WorldSettings.ResolveLeaseTtlSeconds(settings)),
                LeaseGrace = TimeSpan.FromSeconds(WorldSettings.ResolveLeaseGraceSeconds(settings)),
                Heartbeat = TimeSpan.FromMilliseconds(WorldSettings.ResolveHeartbeatMilliseconds(settings)),
                HandoffLifetime = TimeSpan.FromSeconds(ResolveHandoffSeconds()),
                Token = token,
                ServerCertificate = certificate
            };
        }

        static Uri ResolveWorldUrl(WorldSettings? settings)
        {
            string value = WorldSettings.ResolveUrl(settings);
            if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? url)
                || (url.Scheme != Uri.UriSchemeHttp && url.Scheme != Uri.UriSchemeHttps))
                throw new InvalidOperationException("World Url must be an absolute HTTP or HTTPS address.");
            return url;
        }

        static bool IsLoopback(Uri address)
        {
            if (address.IsLoopback) return true;
            return IPAddress.TryParse(address.DnsSafeHost, out IPAddress? host) && IPAddress.IsLoopback(host);
        }

        static X509Certificate2 LoadServerCertificate()
        {
            string? path = Environment.GetEnvironmentVariable(CertificatePathVariable);
            if (string.IsNullOrWhiteSpace(path))
                throw new InvalidOperationException(
                    CertificatePathVariable + " must name a PKCS#12 certificate when World uses HTTPS.");

            X509Certificate2 certificate = X509CertificateLoader.LoadPkcs12FromFile(
                path.Trim(), Environment.GetEnvironmentVariable(CertificatePasswordVariable),
                X509KeyStorageFlags.EphemeralKeySet);
            if (!certificate.HasPrivateKey)
            {
                certificate.Dispose();
                throw new InvalidOperationException("The World TLS certificate must include its private key.");
            }

            return certificate;
        }

        /// <summary>The same knob and bounds the file-based handoff store used.</summary>
        static int ResolveHandoffSeconds()
            => int.TryParse(Environment.GetEnvironmentVariable("AO_REBIRTH_LOGIN_HANDOFF_TIMEOUT_SECONDS"),
                NumberStyles.Integer, CultureInfo.InvariantCulture, out int seconds) && seconds >= 5 && seconds <= 120
                ? seconds
                : 30;
    }
}
