using System.Buffers;
using System.Runtime.CompilerServices;
using System.Text;
using RinhaFraudDetection.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<VectorSearchService>();

builder.WebHost.ConfigureKestrel(o =>
{
    o.AllowSynchronousIO = true;
    o.Limits.MaxConcurrentConnections = int.MaxValue;
    o.Limits.MaxConcurrentUpgradedConnections = int.MaxValue;
    o.Limits.MaxRequestBodySize = 4096;
    o.Limits.MinRequestBodyDataRate = null;
    o.Limits.MinResponseDataRate = null;
});

ThreadPool.SetMinThreads(Environment.ProcessorCount * 4, Environment.ProcessorCount * 4);

var sockPath = Environment.GetEnvironmentVariable("SOCK");
if (!string.IsNullOrEmpty(sockPath))
{
    if (File.Exists(sockPath)) File.Delete(sockPath);
    var dir = Path.GetDirectoryName(sockPath);
    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
    builder.WebHost.ConfigureKestrel(o => o.ListenUnixSocket(sockPath));
}
else
{
    builder.WebHost.ConfigureKestrel(o => o.ListenAnyIP(8080));
}

var app = builder.Build();

var vectorService = app.Services.GetRequiredService<VectorSearchService>();
vectorService.LoadData();
const int NeighborVotes = 5;
const int MaxBodySize = 4096;
var rejectMinFraudCount = ReadEnvInt("REJECT_MIN_FRAUD_COUNT", 3, 1, NeighborVotes);

if (!string.IsNullOrEmpty(sockPath))
{
    app.Lifetime.ApplicationStarted.Register(() =>
    {
        try
        {
            if (File.Exists(sockPath))
            {
                using var chmod = System.Diagnostics.Process.Start("chmod", $"666 {sockPath}");
                chmod?.WaitForExit(1000);
            }
        }
        catch { }
    });
}

app.MapGet("/ready", () => vectorService.IsReady ? Results.Ok() : Results.StatusCode(503));

app.MapPost("/fraud-score", async ctx =>
{
    if (!vectorService.IsReady)
    {
        ctx.Response.StatusCode = 503;
        return;
    }

    byte[]? buf = null;
    var read = 0;
    int fraudCount;
    try
    {
        if (ctx.Request.ContentLength is long declaredLength)
        {
            if (declaredLength <= 0 || declaredLength > MaxBodySize)
            {
                ctx.Response.StatusCode = 400;
                return;
            }

            var bodyLength = (int)declaredLength;
            buf = ArrayPool<byte>.Shared.Rent(bodyLength);
            try
            {
                await ctx.Request.Body.ReadExactlyAsync(buf.AsMemory(0, bodyLength), ctx.RequestAborted);
                read = bodyLength;
            }
            catch (EndOfStreamException)
            {
                ctx.Response.StatusCode = 400;
                return;
            }
        }
        else
        {
            await using var unknownBody = new MemoryStream(512);
            await ctx.Request.Body.CopyToAsync(unknownBody, ctx.RequestAborted);
            if (unknownBody.Length <= 0 || unknownBody.Length > MaxBodySize)
            {
                ctx.Response.StatusCode = 400;
                return;
            }

            read = (int)unknownBody.Length;
            buf = ArrayPool<byte>.Shared.Rent(read);
            unknownBody.Position = 0;
            var copied = unknownBody.Read(buf, 0, read);
            if (copied != read)
            {
                ctx.Response.StatusCode = 400;
                return;
            }
        }

        try
        {
            fraudCount = ParseAndDetect(buf.AsSpan(0, read), vectorService);
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or IndexOutOfRangeException or FormatException or InvalidOperationException)
        {
            ctx.Response.StatusCode = 400;
            return;
        }
    }
    finally
    {
        if (buf is not null) ArrayPool<byte>.Shared.Return(buf);
    }

    fraudCount = Math.Clamp(fraudCount, 0, NeighborVotes);
    var approved = fraudCount < rejectMinFraudCount;

    ctx.Response.StatusCode = 200;
    ctx.Response.ContentType = "application/json";
    ctx.Response.ContentLength = approved ? 35 : 36;

    Span<byte> resp = stackalloc byte[40];
    resp.Clear();
    var pos = 0;
    "{"u8.CopyTo(resp[pos..]); pos += 1;
    "\"approved\":"u8.CopyTo(resp[pos..]); pos += 11;
    if (approved) { "true"u8.CopyTo(resp[pos..]); pos += 4; }
    else { "false"u8.CopyTo(resp[pos..]); pos += 5; }
    ",\"fraud_score\":"u8.CopyTo(resp[pos..]); pos += 15;
    ReadOnlySpan<byte> scoreStr = fraudCount switch
    {
        0 => "0.0"u8,
        1 => "0.2"u8,
        2 => "0.4"u8,
        3 => "0.6"u8,
        4 => "0.8"u8,
        _ => "1.0"u8
    };
    scoreStr.CopyTo(resp[pos..]); pos += scoreStr.Length;
    resp[pos++] = (byte)'}';

    ctx.Response.Body.Write(resp[..pos]);
});

app.Run();

[MethodImpl(MethodImplOptions.AggressiveInlining)]
static int ParseAndDetect(ReadOnlySpan<byte> buf, VectorSearchService svc)
{
    var p = 0;
    var len = buf.Length;

    SkipToKey(ref p, buf, "amount"u8);
    var amount = ScanFloat(ref p, buf);

    SkipToKey(ref p, buf, "installments"u8);
    var installments = ScanInt(ref p, buf);

    SkipToKey(ref p, buf, "requested_at"u8);
    var (reqYear, reqMo, reqDay, reqHour, reqMin) = ScanDateTime(ref p, buf);

    SkipToKey(ref p, buf, "avg_amount"u8);
    var avgAmount = ScanFloat(ref p, buf);

    SkipToKey(ref p, buf, "tx_count_24h"u8);
    var txCount = ScanInt(ref p, buf);

    SkipToKey(ref p, buf, "known_merchants"u8);
    var merchantSlices = ScanStringArray(ref p, buf);

    SkipToKey(ref p, buf, "id"u8);
    var merchantId = ScanStringSpan(ref p, buf);

    SkipToKey(ref p, buf, "mcc"u8);
    var mccSpan = ScanStringSpan(ref p, buf);

    SkipToKey(ref p, buf, "avg_amount"u8);
    var merchantAvgAmount = ScanFloat(ref p, buf);

    SkipToKey(ref p, buf, "is_online"u8);
    var isOnline = ScanBool(ref p, buf);

    SkipToKey(ref p, buf, "card_present"u8);
    var cardPresent = ScanBool(ref p, buf);

    SkipToKey(ref p, buf, "km_from_home"u8);
    var kmFromHome = ScanFloat(ref p, buf);

    SkipToKey(ref p, buf, "last_transaction"u8);
    bool hasLastTx;
    double minutesSinceLast = 0, kmFromCurrent = 0;
    if (p < len && buf[p] == 'n')
    {
        hasLastTx = false;
    }
    else
    {
        hasLastTx = true;
        SkipToKey(ref p, buf, "timestamp"u8);
        var (lastYear, lastMo, lastDay, lastHour, lastMin) = ScanDateTime(ref p, buf);

        SkipToKey(ref p, buf, "km_from_current"u8);
        kmFromCurrent = ScanFloat(ref p, buf);

        minutesSinceLast = MinutesBetween(lastYear, lastMo, lastDay, lastHour, lastMin,
                                           reqYear, reqMo, reqDay, reqHour, reqMin);
    }

    var isUnknownMerchant = true;
    if (merchantSlices != null && merchantId.Length > 0)
    {
        for (var i = 0; i < merchantSlices.Count; i++)
        {
            var s = merchantSlices[i].Span;
            if (s.Length == merchantId.Length && s.SequenceEqual(merchantId))
            {
                isUnknownMerchant = false;
                break;
            }
        }
    }

    Span<char> mccBuf = stackalloc char[8];
    var mccLen = Math.Min(mccSpan.Length, 8);
    for (var i = 0; i < mccLen; i++) mccBuf[i] = (char)mccSpan[i];

    return svc.VectorizeAndSearch(
        amount, installments, reqHour, DayOfWeek(reqYear, reqMo, reqDay),
        avgAmount, txCount,
        mccBuf.Slice(0, mccLen), merchantAvgAmount,
        isOnline, cardPresent, kmFromHome,
        hasLastTx, minutesSinceLast, kmFromCurrent,
        isUnknownMerchant);
}

[MethodImpl(MethodImplOptions.AggressiveInlining)]
static void SkipToKey(ref int p, ReadOnlySpan<byte> buf, ReadOnlySpan<byte> key)
{
    var len = buf.Length;
    var keyLen = key.Length;
    var keyTokenLen = keyLen + 2; // opening + closing quotes
    while (p <= len - keyTokenLen)
    {
        if (buf[p] != '"') { p++; continue; }
        if (buf.Slice(p + 1, keyLen).SequenceEqual(key) && buf[p + 1 + keyLen] == '"')
        {
            p += 1 + keyLen + 1;
            while (p < len && buf[p] != ':') p++;
            p++;
            while (p < len && (buf[p] == ' ' || buf[p] == '\t' || buf[p] == '\n' || buf[p] == '\r')) p++;
            return;
        }
        p++;
    }
    p = len;
}

[MethodImpl(MethodImplOptions.AggressiveInlining)]
static double ScanFloat(ref int p, ReadOnlySpan<byte> buf)
{
    var neg = false;
    if (p < buf.Length && buf[p] == '-') { neg = true; p++; }
    long intPart = 0;
    while (p < buf.Length && (uint)(buf[p] - '0') <= 9)
        intPart = intPart * 10 + (buf[p++] - '0');
    double v = intPart;
    if (p < buf.Length && buf[p] == '.')
    {
        p++;
        double frac = 0, div = 1;
        while (p < buf.Length && (uint)(buf[p] - '0') <= 9)
        {
            frac = frac * 10 + (buf[p++] - '0');
            div *= 10;
        }
        v += frac / div;
    }
    return neg ? -v : v;
}

[MethodImpl(MethodImplOptions.AggressiveInlining)]
static int ScanInt(ref int p, ReadOnlySpan<byte> buf)
{
    var v = 0;
    while (p < buf.Length && (uint)(buf[p] - '0') <= 9)
        v = v * 10 + (buf[p++] - '0');
    return v;
}

[MethodImpl(MethodImplOptions.AggressiveInlining)]
static bool ScanBool(ref int p, ReadOnlySpan<byte> buf)
{
    if (p < buf.Length && buf[p] == 't') { p += 4; return true; }
    p += 5;
    return false;
}

[MethodImpl(MethodImplOptions.AggressiveInlining)]
static ReadOnlySpan<byte> ScanStringSpan(ref int p, ReadOnlySpan<byte> buf)
{
    if (p < buf.Length && buf[p] == '"') p++;
    var start = p;
    while (p < buf.Length && buf[p] != '"') p++;
    var result = buf.Slice(start, p - start);
    if (p < buf.Length) p++;
    return result;
}

static List<ReadOnlyMemory<byte>>? ScanStringArray(ref int p, ReadOnlySpan<byte> buf)
{
    var len = buf.Length;
    if (p < len && buf[p] == 'n') { p += 4; return null; }
    if (p < len && buf[p] == '[') p++;

    var list = new List<ReadOnlyMemory<byte>>(4);
    while (p < len && buf[p] != ']')
    {
        if (buf[p] == '"')
        {
            p++;
            var start = p;
            while (p < len && buf[p] != '"') p++;
            list.Add(buf.Slice(start, p - start).ToArray());
            if (p < len) p++;
        }
        else
        {
            p++;
        }
    }
    if (p < len) p++;
    return list;
}

[MethodImpl(MethodImplOptions.AggressiveInlining)]
static (int year, int mo, int day, int hour, int min) ScanDateTime(ref int p, ReadOnlySpan<byte> buf)
{
    if (p < buf.Length && buf[p] == '"') p++;
    if (p + 19 > buf.Length) return (2025, 1, 1, 12, 0);

    var y = (buf[p] - '0') * 1000 + (buf[p + 1] - '0') * 100 + (buf[p + 2] - '0') * 10 + (buf[p + 3] - '0');
    var mo = (buf[p + 5] - '0') * 10 + (buf[p + 6] - '0');
    var d = (buf[p + 8] - '0') * 10 + (buf[p + 9] - '0');
    var h = (buf[p + 11] - '0') * 10 + (buf[p + 12] - '0');
    var mi = (buf[p + 14] - '0') * 10 + (buf[p + 15] - '0');
    p += 19;
    while (p < buf.Length && buf[p] != '"') p++;
    if (p < buf.Length) p++;

    return (y, mo, d, h, mi);
}

[MethodImpl(MethodImplOptions.AggressiveInlining)]
static int DayOfWeek(int y, int m, int d)
{
    ReadOnlySpan<int> t = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    var ya = m < 3 ? y - 1 : y;
    var dow = (ya + ya / 4 - ya / 100 + ya / 400 + t[m - 1] + d) % 7;
    return (dow + 6) % 7;
}

[MethodImpl(MethodImplOptions.AggressiveInlining)]
static long DaysSinceEpoch(int y, int m, int d)
{
    if (m <= 2) y--;
    var era = y >= 0 ? y / 400 : (y - 399) / 400;
    var yoe = y - era * 400;
    var mm = m > 2 ? m - 3 : m + 9;
    var doy = (153 * mm + 2) / 5 + d - 1;
    var doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (long)era * 146097 + doe - 719468;
}

[MethodImpl(MethodImplOptions.AggressiveInlining)]
static double MinutesBetween(int y1, int mo1, int d1, int h1, int mi1, int y2, int mo2, int d2, int h2, int mi2)
{
    var m1 = DaysSinceEpoch(y1, mo1, d1) * 1440 + h1 * 60 + mi1;
    var m2 = DaysSinceEpoch(y2, mo2, d2) * 1440 + h2 * 60 + mi2;
    return Math.Max(0, m2 - m1);
}

[MethodImpl(MethodImplOptions.AggressiveInlining)]
static int ReadEnvInt(string key, int fallback, int min, int max)
{
    var raw = Environment.GetEnvironmentVariable(key);
    if (!string.IsNullOrEmpty(raw) && int.TryParse(raw, out var parsed))
        return Math.Clamp(parsed, min, max);
    return fallback;
}
