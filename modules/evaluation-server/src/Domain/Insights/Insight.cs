using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Domain.EndUsers;

namespace Domain.Insights;

public class Insight
{
    public virtual EndUser? User { get; set; }

    public IEnumerable<VariationInsight> Variations { get; set; } = Array.Empty<VariationInsight>();

    public IEnumerable<MetricInsight> Metrics { get; set; } = Array.Empty<MetricInsight>();

    public virtual bool IsValid()
    {
        foreach (var variation in Variations)
        {
            var validationResults = ValidateModel(variation);
            if (validationResults.Any())
            {
                return false;
            }
        }

        foreach (var metric in Metrics)
        {
            var validationResults = ValidateModel(metric);
            if (validationResults.Any())
            {
                return false;
            }
        }

        return User != null && User.IsValid();
    }

    private IList<ValidationResult> ValidateModel(object model)
    {
        var validationResults = new List<ValidationResult>();
        var validationContext = new ValidationContext(model, null, null);
        Validator.TryValidateObject(model, validationContext, validationResults, true);
        return validationResults;
    }

    public virtual EndUserMessage EndUserMessage(Guid envId)
    {
        return new EndUserMessage(envId, User!);
    }

    public virtual ICollection<InsightMessage> InsightMessages(Guid envId)
    {
        var messages = new List<InsightMessage>();

        // flag messages
        foreach (var variation in Variations)
        {
            var flagId = $"{envId}-{variation.FeatureFlagKey}";
            var properties = new
            {
                route = "/Variation/GetMultiOptionVariation",
                flagId = flagId,
                envId = envId.ToString(),
                accountId = string.Empty,
                projectId = string.Empty,
                featureFlagKey = variation.FeatureFlagKey,
                sendToExperiment = variation.SendToExperiment,
                userKeyId = User!.KeyId,
                userName = User!.Name,
                variationId = variation.Variation.Id,
                tag_0 = User!.KeyId,
                tag_1 = variation.Variation.Id,
                tag_2 = variation.SendToExperiment ? "true" : "false",
                tag_3 = User!.Name
            };

            var message = new InsightMessage
            {
                Uuid = Guid.NewGuid().ToString(),
                DistinctId = flagId,
                EnvId = envId.ToString(),
                Event = "FlagValue",
                Properties = JsonSerializer.Serialize(properties),
                Timestamp = variation.Timestamp * 1000 // milliseconds to microseconds
            };

            messages.Add(message);
        }

        // metric messages
        foreach (var metric in Metrics)
        {
            var properties = new
            {
                route = metric.Route,
                type = metric.Type,
                eventName = metric.EventName,
                numericValue = metric.NumericValue,
                user = new { keyId = User!.KeyId, name = User!.Name },
                applicationType = metric.AppType,
                projectId = string.Empty,
                envId = envId.ToString(),
                accountId = string.Empty,
                tag_0 = User!.KeyId,
                tag_1 = metric.NumericValue.ToString(),
                tag_2 = User!.Name
            };

            var message = new InsightMessage
            {
                Uuid = Guid.NewGuid().ToString(),
                DistinctId = metric.EventName,
                EnvId = envId.ToString(),
                Event = metric.Type,
                Properties = JsonSerializer.Serialize(properties),
                Timestamp = metric.Timestamp * 1000 // milliseconds to microseconds
            };

            messages.Add(message);
        }

        return messages;
    }
}