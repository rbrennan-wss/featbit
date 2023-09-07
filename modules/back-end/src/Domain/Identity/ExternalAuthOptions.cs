namespace Domain.Identity
{
    public class ExternalAuthOptions
    {
        public const string ExternalAuth = nameof(ExternalAuth);
        public bool Enabled { get; set; }
        public string Authority { get; set; }
        public string Token_Endpoint { get; set; }
        public string Auth_Endpoint { get; set; }
    }
}