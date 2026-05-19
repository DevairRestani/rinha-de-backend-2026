using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

if (args.Length < 2)
{
    Console.WriteLine("Usage: Preprocess <input.json.gz> <output.bin>");
    return 1;
}

var inputPath = args[0];
var outputPath = args[1];

const int Dim = 14;
const int BlockSlots = 8;
const int BlockSize = Dim * BlockSlots;
const int NumClusters = 256;
const int KmeansIterations = 8;
const int SampleSize = 300_000;

var capacity = 3_500_000;
var rawVectors = new float[capacity * Dim];
var labelBytes = new byte[capacity];
var count = 0;

await using (var fs = File.OpenRead(inputPath))
await using (var gz = new GZipStream(fs, CompressionMode.Decompress))
{
    await foreach (var elem in JsonSerializer.DeserializeAsyncEnumerable<JsonElement>(gz))
    {
        if (elem.ValueKind == JsonValueKind.Null) continue;

        if (count >= capacity)
        {
            capacity *= 2;
            Array.Resize(ref rawVectors, capacity * Dim);
            Array.Resize(ref labelBytes, capacity);
        }

        var vec = elem.GetProperty("vector");
        var label = elem.GetProperty("label").GetString();
        var baseIdx = count * Dim;
        for (var d = 0; d < Dim; d++)
            rawVectors[baseIdx + d] = (float)vec[d].GetDouble();
        labelBytes[count] = label == "fraud" ? (byte)1 : (byte)0;
        count++;
    }
}

if (count < capacity)
{
    Array.Resize(ref rawVectors, count * Dim);
    Array.Resize(ref labelBytes, count);
}

Console.WriteLine($"Loaded {count} vectors. Running K-means ({NumClusters} clusters, {KmeansIterations} iterations)...");

var rng = new Random(42);
var actualNumClusters = Math.Min(NumClusters, count);
var sampleSize = Math.Min(SampleSize, count);

var centroids = new float[actualNumClusters * Dim];
var step = sampleSize / actualNumClusters;
for (var c = 0; c < actualNumClusters; c++)
{
    var si = c * step + rng.Next(Math.Min(step, count - c * step));
    if (si >= count) si = rng.Next(count);
    var sBase = si * Dim;
    for (var d = 0; d < Dim; d++)
        centroids[c * Dim + d] = rawVectors[sBase + d];
}

var sampleIndices = new int[sampleSize];
for (var i = 0; i < sampleSize; i++)
    sampleIndices[i] = rng.Next(count);

var sampleAssignments = new int[sampleSize];

for (var iter = 0; iter < KmeansIterations; iter++)
{
    for (var s = 0; s < sampleSize; s++)
    {
        var sBase = sampleIndices[s] * Dim;
        var bestDist = float.MaxValue;
        var bestC = 0;
        for (var c = 0; c < actualNumClusters; c++)
        {
            var cBase = c * Dim;
            var dist = 0.0f;
            for (var d = 0; d < Dim; d++)
            {
                var diff = rawVectors[sBase + d] - centroids[cBase + d];
                dist += diff * diff;
            }
            if (dist < bestDist) { bestDist = dist; bestC = c; }
        }
        sampleAssignments[s] = bestC;
    }

    var sums = new float[actualNumClusters * Dim];
    var cCounts = new int[actualNumClusters];
    for (var s = 0; s < sampleSize; s++)
    {
        var c = sampleAssignments[s];
        var sBase = sampleIndices[s] * Dim;
        var cBase = c * Dim;
        cCounts[c]++;
        for (var d = 0; d < Dim; d++)
            sums[cBase + d] += rawVectors[sBase + d];
    }
    for (var c = 0; c < actualNumClusters; c++)
    {
        if (cCounts[c] == 0) continue;
        var cBase = c * Dim;
        for (var d = 0; d < Dim; d++)
            centroids[cBase + d] = sums[cBase + d] / cCounts[c];
    }

    Console.WriteLine($"  K-means iteration {iter + 1}/{KmeansIterations}");
}

Console.WriteLine("Assigning all vectors to clusters...");
var assignments = new int[count];
for (var i = 0; i < count; i++)
{
    var vBase = i * Dim;
    var bestDist = float.MaxValue;
    var bestC = 0;
    for (var c = 0; c < actualNumClusters; c++)
    {
        var cBase = c * Dim;
        var dist = 0.0f;
        for (var d = 0; d < Dim; d++)
        {
            var diff = rawVectors[vBase + d] - centroids[cBase + d];
            dist += diff * diff;
        }
        if (dist < bestDist) { bestDist = dist; bestC = c; }
    }
    assignments[i] = bestC;
}

var clusterCounts = new int[actualNumClusters];
for (var i = 0; i < count; i++)
    clusterCounts[assignments[i]]++;

var clusterOffsets = new int[actualNumClusters + 1];
for (var c = 0; c < actualNumClusters; c++)
    clusterOffsets[c + 1] = clusterOffsets[c] + clusterCounts[c];

var sortedIndices = new int[count];
var tempOffsets = new int[actualNumClusters];
Array.Copy(clusterOffsets, tempOffsets, actualNumClusters);
for (var i = 0; i < count; i++)
    sortedIndices[tempOffsets[assignments[i]]++] = i;

var totalBlocks = 0;
for (var c = 0; c < actualNumClusters; c++)
    totalBlocks += (clusterCounts[c] + BlockSlots - 1) / BlockSlots;

var blockOffsets = new int[actualNumClusters + 1];
for (var c = 0; c < actualNumClusters; c++)
    blockOffsets[c + 1] = blockOffsets[c] + (clusterCounts[c] + BlockSlots - 1) / BlockSlots;

var paddedN = totalBlocks * BlockSlots;

Console.WriteLine("Writing output files (SoA block layout)...");

var quantizedVectors = new short[count * Dim];
for (var i = 0; i < count; i++)
{
    var vBase = i * Dim;
    var srcBase = sortedIndices[i] * Dim;
    for (var d = 0; d < Dim; d++)
        quantizedVectors[vBase + d] = (short)Math.Clamp((int)Math.Round(rawVectors[srcBase + d] * 10000f), -32768, 32767);
}

var soaBlocks = new short[totalBlocks * BlockSize];
var soaLabels = new byte[paddedN];

for (var c = 0; c < actualNumClusters; c++)
{
    var vecStart = clusterOffsets[c];
    var vecCount = clusterCounts[c];
    var numBlocks = (vecCount + BlockSlots - 1) / BlockSlots;
    var blockStart = blockOffsets[c];

    for (var bk = 0; bk < numBlocks; bk++)
    {
        var blockBase = (blockStart + bk) * BlockSize;
        var labelBase = (blockStart + bk) * BlockSlots;

        for (var slot = 0; slot < BlockSlots; slot++)
        {
            var vecIdx = vecStart + bk * BlockSlots + slot;
            if (vecIdx < vecStart + vecCount)
            {
                var vBase = vecIdx * Dim;
                for (var d = 0; d < Dim; d++)
                    soaBlocks[blockBase + d * BlockSlots + slot] = quantizedVectors[vBase + d];
                soaLabels[labelBase + slot] = labelBytes[sortedIndices[vecIdx]];
            }
            else
            {
                for (var d = 0; d < Dim; d++)
                    soaBlocks[blockBase + d * BlockSlots + slot] = short.MaxValue;
            }
        }
    }
}

var centroidsTransposed = new float[actualNumClusters * Dim];
for (var c = 0; c < actualNumClusters; c++)
    for (var d = 0; d < Dim; d++)
        centroidsTransposed[d * actualNumClusters + c] = centroids[c * Dim + d];

using (var output = File.Create(outputPath))
using (var writer = new BinaryWriter(output))
{
    writer.Write(Encoding.UTF8.GetBytes("IVF1"));
    writer.Write(count);
    writer.Write(actualNumClusters);
    writer.Write(Dim);

    var centBytes = MemoryMarshal.AsBytes<float>(centroidsTransposed);
    writer.Write(centBytes);

    for (var c = 0; c <= actualNumClusters; c++)
        writer.Write(blockOffsets[c]);

    writer.Write(soaLabels);

    var blockBytes = MemoryMarshal.AsBytes<short>(soaBlocks);
    writer.Write(blockBytes);
}

Console.WriteLine($"Done: {count} vectors, {actualNumClusters} clusters, {totalBlocks} blocks (padded to {paddedN})");
Console.WriteLine($"  {outputPath}: {new FileInfo(outputPath).Length / (1024.0 * 1024.0):F1} MB");
return 0;
