namespace AuthApi.DTOs;

public class UserRegisterRequest
{
    public string UserName { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;
}