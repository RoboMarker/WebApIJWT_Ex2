namespace WebApIJWT_Ex2
{
    public class User
    {
        public string Username { get; set; }=string.Empty;
        public byte[] PasswordHash { get; set; }
        
        public byte[] PasswordSalt { get; set; }
    }
}
