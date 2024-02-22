namespace ASPDotNetCRUDApp.Configurations
{
    //same name as given in the appsettings
    public class JwtConfig
    {
        public string Secret { get; set; }

        public TimeSpan ExpiryTimeFrame { get; set; }

	}
}
