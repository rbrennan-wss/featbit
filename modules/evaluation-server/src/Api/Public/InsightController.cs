using System.Text.Json.Nodes;
using Api.Setup;
using Domain.EndUsers;
using Domain.Insights;
using Domain.Messages;
using Infrastructure.MongoDb;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using MongoDB.Bson;
using MongoDB.Driver;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;

namespace Api.Public;

public class InsightController : PublicApiControllerBase
{
    private readonly IMessageProducer _producer;
    private readonly IMongoDbClient _mongodb;
    private readonly MemoryCache _cache;
    private readonly MemoryCacheEntryOptions _cacheEntryOptions;

    public InsightController(IMessageProducer producer, IMongoDbClient mongodb, BoundedMemoryCache boundedMemoryCache)
    {
        _producer = producer;
        _mongodb = mongodb;
        _cache = boundedMemoryCache.Instance;
        _cacheEntryOptions = new MemoryCacheEntryOptions
        {
            Size = 1,
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(3)
        };
    }

    [HttpPost("track")]
    public async Task<IActionResult> TrackAsync(ICollection<Insight> insights)
    {
        if (!Authenticated)
        {
            return Unauthorized();
        }

        var validInsights = insights.Where(x => x.IsValid()).ToArray();
        if (!validInsights.Any())
        {
            return Ok();
        }

        var envId = EnvId;

        var endUserMessages = new List<EndUserMessage>();
        var insightMessages = new List<InsightMessage>();
        foreach (var insight in validInsights)
        {
            var key = $"{envId:N}:{insight.User!.KeyId}";
            if (!_cache.TryGetValue(key, out _))
            {
                _cache.Set(key, string.Empty, _cacheEntryOptions);
                endUserMessages.Add(insight.EndUserMessage(envId));
            }

            foreach (var message in insight.InsightMessages(envId))
            {
                var properties = JsonNode.Parse(message.Properties);
                var flagKey = properties["featureFlagKey"].ToString();
                if (await CheckInsightsEnabled(envId, flagKey))
                {
                    insightMessages.Add(message);
                }
            }
        }

        await Task.WhenAll(
            endUserMessages.Select(x => _producer.PublishAsync(Topics.EndUser, x))
        );
        await Task.WhenAll(
            insightMessages.Select(x => _producer.PublishAsync(Topics.Insights, x))
        );

        return Ok();
    }

    private async Task<bool> CheckInsightsEnabled(Guid envId, string flagKey)
    {
        try
        {
            if (_mongodb == null)
            {
                throw new InvalidOperationException("MongoDbClient is not initialized.");
            }

            var result = true;

            var database = _mongodb.Database;
            var collection = database.GetCollection<BsonDocument>("FeatureFlags");

            var filter = Builders<BsonDocument>.Filter.And(
                Builders<BsonDocument>.Filter.Eq("envId", envId),
                Builders<BsonDocument>.Filter.Eq("key", flagKey)
            );

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

            return result;
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            return false;
        }
    }
}