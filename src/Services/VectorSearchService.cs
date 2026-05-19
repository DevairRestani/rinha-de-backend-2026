using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace RinhaFraudDetection.Services;

public sealed class VectorSearchService
{
    private short[] _blocks = [];
    private byte[] _labels = [];
    private float[] _centroidsT = [];
    private int[] _blockOffsets = [];
    private int _numClusters;
    private int _vectorCount;
    private int _totalBlocks;
    private volatile bool _isReady;

    private static readonly int[] MccKeys = [5411, 5812, 5912, 5944, 7801, 7802, 7995, 4511, 5311, 5999];
    private static readonly float[] MccValues = [0.15f, 0.30f, 0.20f, 0.45f, 0.80f, 0.75f, 0.85f, 0.35f, 0.25f, 0.50f];
    private const int MccMask = 16384 - 1;
    private readonly float[] _mccRisk = new float[16384];

    private const float MaxAmount = 10000f;
    private const float MaxInstallments = 12f;
    private const float AmountVsAvgRatio = 10f;
    private const float MaxMinutes = 1440f;
    private const float MaxKm = 1000f;
    private const float MaxTxCount24h = 20f;
    private const float MaxMerchantAvgAmount = 10000f;

    private const int Dim = 14;
    private const int BlockSlots = 8;
    private const int BlockSize = Dim * BlockSlots;
    private const int K = 5;
    private readonly int _fastProbes;
    private readonly int _fullProbes;
    private readonly int _hardQueryProbes;
    private readonly int _borderlineMinVotes;
    private readonly int _borderlineMaxVotes;
    private readonly bool _hardQueryEnabled;
    private readonly bool _highConfidenceFraudBumpEnabled;

    public bool IsReady => _isReady;

    public VectorSearchService()
    {
        _fastProbes = ReadEnvInt("FAST_PROBES", 5, 1, 256);
        _fullProbes = ReadEnvInt("FULL_PROBES", 20, _fastProbes, 256);
        _hardQueryProbes = ReadEnvInt("HARD_QUERY_PROBES", 24, _fullProbes, 256);
        _borderlineMinVotes = ReadEnvInt("BORDERLINE_MIN_VOTES", 1, 0, K);
        _borderlineMaxVotes = ReadEnvInt("BORDERLINE_MAX_VOTES", 3, _borderlineMinVotes, K);
        _hardQueryEnabled = ReadEnvBool("HARD_QUERY_ENABLED", false);
        _highConfidenceFraudBumpEnabled = ReadEnvBool("HIGH_CONFIDENCE_FRAUD_BUMP", false);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int ReadEnvInt(string key, int fallback, int min, int max)
    {
        var raw = Environment.GetEnvironmentVariable(key);
        if (!string.IsNullOrEmpty(raw) && int.TryParse(raw, out var parsed))
            return Math.Clamp(parsed, min, max);
        return fallback;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool ReadEnvBool(string key, bool fallback)
    {
        var raw = Environment.GetEnvironmentVariable(key);
        if (string.IsNullOrEmpty(raw)) return fallback;
        if (raw == "1" || raw.Equals("true", StringComparison.OrdinalIgnoreCase)) return true;
        if (raw == "0" || raw.Equals("false", StringComparison.OrdinalIgnoreCase)) return false;
        return fallback;
    }

    public void LoadData()
    {
        Array.Fill(_mccRisk, 0.5f);
        for (var i = 0; i < MccKeys.Length; i++)
            _mccRisk[MccKeys[i] & MccMask] = MccValues[i];

        var dataPath = Environment.GetEnvironmentVariable("DATA_PATH") ?? "Data";
        var binPath = Path.Combine(dataPath, "references.bin");

        using var fs = File.OpenRead(binPath);
        using var reader = new BinaryReader(fs);

        var magic = reader.ReadBytes(4);
        if (magic[0] != (byte)'I' || magic[1] != (byte)'V' || magic[2] != (byte)'F' || magic[3] != (byte)'1')
            throw new InvalidDataException("Invalid index file magic");

        _vectorCount = reader.ReadInt32();
        _numClusters = reader.ReadInt32();
        var dim = reader.ReadInt32();
        if (dim != Dim)
            throw new InvalidDataException($"Expected dim={Dim}, got {dim}");

        _centroidsT = new float[Dim * _numClusters];
        for (var i = 0; i < _centroidsT.Length; i++)
            _centroidsT[i] = reader.ReadSingle();

        _blockOffsets = new int[_numClusters + 1];
        for (var c = 0; c <= _numClusters; c++)
            _blockOffsets[c] = reader.ReadInt32();

        _totalBlocks = _blockOffsets[_numClusters];
        var paddedN = _totalBlocks * BlockSlots;

        _labels = reader.ReadBytes(paddedN);

        var blockShortCount = _totalBlocks * BlockSize;
        _blocks = new short[blockShortCount];
        var blockBytes = MemoryMarshal.AsBytes<short>(_blocks.AsSpan());
        var remaining = blockShortCount * 2;
        var offset = 0;
        while (remaining > 0)
        {
            var read = reader.Read(blockBytes.Slice(offset, remaining));
            if (read <= 0) break;
            offset += read;
            remaining -= read;
        }

        _isReady = true;
        Console.WriteLine($"Loaded {_vectorCount} vectors in {_numClusters} clusters ({_totalBlocks} blocks). Ready.");

        Warmup();
    }

    private void Warmup()
    {
        Console.Write("Warming up...");
        Span<char> mcc = stackalloc char[4];
        "5411".AsSpan().CopyTo(mcc);
        for (var i = 0; i < 200; i++)
        {
            VectorizeAndSearch(
                500.0, 3, 14, 30, 500.0, 2,
                mcc, 200.0,
                true, false, 50.0,
                true, 60.0, 10.0);
        }
        Console.WriteLine(" done.");
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float Round4(float x) => MathF.Round(x * 10000f) * 0.0001f;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float Clamp01(float v) => Math.Clamp(Round4(v), 0f, 1f);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private float GetMccRisk(int mcc) => _mccRisk[mcc & MccMask];

    public int VectorizeAndSearch(
        double amount, int installments, int hour, int dayOfWeek,
        double avgAmount, int txCount24h,
        ReadOnlySpan<char> mcc, double merchantAvgAmount,
        bool isOnline, bool cardPresent, double kmFromHome,
        bool hasLastTx, double minutesSinceLast, double kmFromCurrent,
        bool isUnknownMerchant = true)
    {
        Span<float> q = stackalloc float[Dim];
        q[0] = Clamp01((float)amount / MaxAmount);
        q[1] = Clamp01(installments / MaxInstallments);
        var ratio = avgAmount > 0 ? (float)(amount / avgAmount) / AmountVsAvgRatio : 1f;
        q[2] = Clamp01(ratio);
        q[3] = Round4(hour / 23f);
        q[4] = Round4(dayOfWeek / 6f);
        if (hasLastTx)
        {
            q[5] = Clamp01((float)minutesSinceLast / MaxMinutes);
            q[6] = Clamp01((float)kmFromCurrent / MaxKm);
        }
        else
        {
            q[5] = -1f;
            q[6] = -1f;
        }
        q[7] = Clamp01((float)kmFromHome / MaxKm);
        q[8] = Clamp01(txCount24h / MaxTxCount24h);
        q[9] = isOnline ? 1f : 0f;
        q[10] = cardPresent ? 1f : 0f;
        q[11] = isUnknownMerchant ? 1f : 0f;
        var mccInt = 0;
        for (var i = 0; i < mcc.Length; i++) { var c = mcc[i]; if (c < '0' || c > '9') break; mccInt = mccInt * 10 + (c - '0'); }
        q[12] = GetMccRisk(mccInt);
        q[13] = Clamp01((float)merchantAvgAmount / MaxMerchantAvgAmount);

        var isHardQuery = IsHardQuery(q);
        var fraudCount = KnnSearch(q, isHardQuery);
        if (_highConfidenceFraudBumpEnabled && fraudCount < 3)
        {
            if (IsVeryHighConfidenceFraud(q))
                return 3;

            if (fraudCount == 2 && IsHighConfidenceFraud(q))
                return 3;
        }
        return fraudCount;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool IsHardQuery(ReadOnlySpan<float> query)
    {
        if (!_hardQueryEnabled) return false;
        var highAmountVsAverage = query[2] >= 0.90f;
        var unknownMerchant = query[11] >= 0.5f;
        var onlineWithoutCard = query[9] >= 0.5f && query[10] <= 0.5f;
        var highDistanceOrVelocity = query[7] >= 0.75f || query[8] >= 0.8f;
        return highAmountVsAverage && unknownMerchant && onlineWithoutCard && highDistanceOrVelocity;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsVeryHighConfidenceFraud(ReadOnlySpan<float> query)
    {
        var highAmountVsAverage = query[2] >= 0.90f;
        var unknownMerchant = query[11] >= 0.5f;
        var onlineWithoutCard = query[9] >= 0.5f && query[10] <= 0.5f;
        var highDistanceOrVelocity = query[7] >= 0.60f || query[8] >= 0.60f;
        return highAmountVsAverage && unknownMerchant && onlineWithoutCard && highDistanceOrVelocity;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsHighConfidenceFraud(ReadOnlySpan<float> query)
    {
        var unknownMerchant = query[11] >= 0.5f;
        var onlineWithoutCard = query[9] >= 0.5f && query[10] <= 0.5f;
        var highMccRisk = query[12] >= 0.75f;
        var elevatedAmountVsAverage = query[2] >= 0.60f;
        var highDistanceOrVelocity = query[7] >= 0.50f || query[8] >= 0.50f;
        return unknownMerchant && onlineWithoutCard && highMccRisk && elevatedAmountVsAverage && highDistanceOrVelocity;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void FindTopNClusters(ReadOnlySpan<float> query, int n, Span<int> probeClusters, Span<float> probeDists)
    {
        var centroids = _centroidsT;
        var k = _numClusters;

        probeDists.Fill(float.MaxValue);

        for (var c = 0; c < k; c++)
        {
            var dist = 0.0f;
            for (var d = 0; d < Dim; d++)
            {
                var diff = query[d] - centroids[d * k + c];
                dist += diff * diff;
            }

            if (dist >= probeDists[n - 1]) continue;

            var pos = n - 1;
            while (pos > 0 && dist < probeDists[pos - 1]) pos--;
            for (var j = n - 1; j > pos; j--)
            {
                probeClusters[j] = probeClusters[j - 1];
                probeDists[j] = probeDists[j - 1];
            }
            probeClusters[pos] = c;
            probeDists[pos] = dist;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private int ScanWithProbes(ReadOnlySpan<float> query, int requestedProbeCount)
    {
        var probeCount = Math.Clamp(requestedProbeCount, 1, _numClusters);
        Span<int> probeClusters = stackalloc int[probeCount];
        Span<float> probeDists = stackalloc float[probeCount];
        FindTopNClusters(query, probeCount, probeClusters, probeDists);
        return ScanBlocks(query, probeClusters);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private int KnnSearch(ReadOnlySpan<float> query, bool isHardQuery)
    {
        var fastResult = ScanWithProbes(query, _fastProbes);
        var isBorderline = fastResult >= _borderlineMinVotes && fastResult <= _borderlineMaxVotes;

        if (!isBorderline)
            return fastResult;

        var fullResult = ScanWithProbes(query, _fullProbes);
        if (!isHardQuery || fullResult != 2 || _hardQueryProbes <= _fullProbes)
            return fullResult;

        return ScanWithProbes(query, _hardQueryProbes);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private int ScanBlocks(ReadOnlySpan<float> query, Span<int> probes)
    {
        float topDist0 = float.MaxValue, topDist1 = float.MaxValue, topDist2 = float.MaxValue, topDist3 = float.MaxValue, topDist4 = float.MaxValue;
        byte topLabel0 = 0, topLabel1 = 0, topLabel2 = 0, topLabel3 = 0, topLabel4 = 0;
        var worstDist = float.MaxValue;
        var worstIdx = 4;

        var blocks = _blocks;
        var labels = _labels;
        var blockOffsets = _blockOffsets;

        for (var p = 0; p < probes.Length; p++)
        {
            var cluster = probes[p];
            var startBlock = blockOffsets[cluster];
            var endBlock = blockOffsets[cluster + 1];

            for (var bi = startBlock; bi < endBlock; bi++)
            {
                var blockBase = bi * BlockSize;
                var labelBase = bi * BlockSlots;

                for (var slot = 0; slot < BlockSlots; slot++)
                {
                    // Padded slots use short.MaxValue as sentinel in dim 0.
                    if (blocks[blockBase + slot] == short.MaxValue) continue;

                    var threshold = worstDist;
                    var dist = 0.0f;
                    var rejected = false;

                    for (var d = 0; d < Dim; d++)
                    {
                        var v = blocks[blockBase + d * BlockSlots + slot] * 0.0001f;
                        var diff = query[d] - v;
                        dist += diff * diff;

                        if (d == 3 || d == 7 || d == 10)
                        {
                            if (dist >= threshold)
                            {
                                rejected = true;
                                break;
                            }
                        }
                    }

                    if (rejected || dist >= threshold) continue;

                    var label = labels[labelBase + slot];
                    switch (worstIdx)
                    {
                        case 0: topDist0 = dist; topLabel0 = label; break;
                        case 1: topDist1 = dist; topLabel1 = label; break;
                        case 2: topDist2 = dist; topLabel2 = label; break;
                        case 3: topDist3 = dist; topLabel3 = label; break;
                        case 4: topDist4 = dist; topLabel4 = label; break;
                    }

                    worstDist = topDist0;
                    worstIdx = 0;
                    if (topDist1 > worstDist) { worstDist = topDist1; worstIdx = 1; }
                    if (topDist2 > worstDist) { worstDist = topDist2; worstIdx = 2; }
                    if (topDist3 > worstDist) { worstDist = topDist3; worstIdx = 3; }
                    if (topDist4 > worstDist) { worstDist = topDist4; worstIdx = 4; }
                }
            }
        }

        var fraudCount = 0;
        if (topDist0 < float.MaxValue && topLabel0 == 1) fraudCount++;
        if (topDist1 < float.MaxValue && topLabel1 == 1) fraudCount++;
        if (topDist2 < float.MaxValue && topLabel2 == 1) fraudCount++;
        if (topDist3 < float.MaxValue && topLabel3 == 1) fraudCount++;
        if (topDist4 < float.MaxValue && topLabel4 == 1) fraudCount++;
        return fraudCount;
    }
}
