using System.Text.Json.Nodes;
using Application.Bases.Exceptions;
using Domain.FeatureFlags;
using Domain.Messages;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Logging;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Infrastructure.Messages;

public class InsightMessageHandler : IMessageHandler, IDisposable
{
    public string Topic => Topics.Insights;

    private readonly IMongoCollection<BsonDocument> _events;
    private readonly List<BsonDocument> _eventsBuffer;

    private readonly PeriodicTimer _timer;
    private readonly Task _flushWorker;

    private readonly ILogger<InsightMessageHandler> _logger;

    private readonly MongoDbClient _mongodb;

    public InsightMessageHandler(MongoDbClient mongodb, ILogger<InsightMessageHandler> logger)
    {
        _mongodb = mongodb;
        _events = mongodb.CollectionOf("Events");
        _eventsBuffer = new List<BsonDocument>();

        _logger = logger;

        _timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        _flushWorker = FlushEventsAsync();
    }

    public Task HandleAsync(string message, CancellationToken cancellationToken)
    {
        var jsonNode = JsonNode.Parse(message)!.AsObject();

        // Replace uuid with _id
        jsonNode["_id"] = jsonNode["uuid"]!.GetValue<string>();
        jsonNode.Remove("uuid");

        // Convert properties JSON string to object
        jsonNode["properties"] = JsonNode.Parse(jsonNode["properties"]!.GetValue<string>());

        if (jsonNode["properties"] != null)
        {
            var properties = jsonNode["properties"].AsObject();
            if (properties["envId"] != null && properties["featureFlagKey"] != null)
            {
                var envId = Guid.Parse(properties["envId"].GetValue<string>());
                var flagKey = properties["featureFlagKey"].GetValue<string>();
                var insightsEnabled = CheckInsightsEnabled(envId, flagKey).Result;

                if (!insightsEnabled)
                {
                    return Task.CompletedTask;
                }
            }
        }

        // Convert timestamp to UTC DateTime
        var timestampInMilliseconds = jsonNode["timestamp"]!.GetValue<long>() / 1000;
        var timestamp = DateTimeOffset.FromUnixTimeMilliseconds(timestampInMilliseconds).UtcDateTime;
        jsonNode["timestamp"] = timestamp;

        // Convert JSON object to BSON document
        var bsonDocument = BsonDocument.Parse(jsonNode.ToJsonString());
        // Change timestamp type to DateTime, otherwise it will be String
        bsonDocument["timestamp"] = timestamp;

        // Add event to buffer
        _eventsBuffer.Add(bsonDocument);

        return Task.CompletedTask;
    }

    private async Task<bool> CheckInsightsEnabled(Guid envId, string flagKey)
    {
        if (_mongodb == null)
        {
            throw new InvalidOperationException("MongoDbClient is not initialized.");
        }

        var result = true;

        var collection = _mongodb.CollectionOf("FeatureFlags");

        // Build the filter
        var filter = Builders<BsonDocument>.Filter.And(
            Builders<BsonDocument>.Filter.Eq("envId", envId),
            Builders<BsonDocument>.Filter.Eq("key", flagKey)
        );

        // Query the collection
        var flag = await collection.Find(filter).FirstOrDefaultAsync();

        if (flag != null)
        {
            BsonValue insightsEnabled;
            var hasInsightValue = flag.TryGetValue("insightsEnabled", out insightsEnabled);
            if (hasInsightValue)
            {
                result = insightsEnabled.AsBoolean;
            }
        }
        // Return true if the flag is found, otherwise false
        return result;
    }

    private async Task FlushEventsAsync()
    {
        _logger.LogDebug("Start Flushing events.");
        try
        {
            while (await _timer.WaitForNextTickAsync())
            {
                if (_eventsBuffer.Count == 0)
                {
                    // If there are no events in the buffer, continue to wait for the next tick.
                    continue;
                }

                // Get snapshots of the events and clear the buffer.
                var snapshots = _eventsBuffer.ToArray();
                _eventsBuffer.Clear();

                // Split each snapshot into groups of 100
                foreach (var chunked in snapshots.Chunk(100))
                {
                    await _events.InsertManyAsync(chunked);
                }

                // Check log level here to avoid unnecessary memory allocation
                if (_logger.IsEnabled(LogLevel.Debug))
                {
                    _logger.LogDebug("{Count} insight events has been handled", snapshots.Length);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception occurred while flushing insight events.");
        }
    }

    public void Dispose()
    {
        // stop the timer
        _timer.Dispose();

        // wait 1 second to flush events
        _flushWorker.Wait(TimeSpan.FromSeconds(1));
        _flushWorker.Dispose();

        GC.SuppressFinalize(this);
    }
}