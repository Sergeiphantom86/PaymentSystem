using System.Security.Cryptography;
using System.Text;

public class Program
{
    static void Main(string[] args)
    {
        var paymentServices = new IPaymentGateway[]
        {
            new BasicPaymentGateway(new MD5Hasher()),
            new AmountAwarePaymentGateway(new MD5Hasher()),
            new SecurePaymentGateway(new SHA1Hasher(), "secret_key_123")
        };

        foreach (var service in paymentServices)
        {
            Console.WriteLine(service.GeneratePaymentUrl(new Order(123, 12000)));
        }
    }
}

public class Order
{
    public readonly int Id;
    public readonly int Amount;

    public Order(int id, int amount)
    {
        if (id <= 0)
            throw new ArgumentOutOfRangeException(nameof(id));
        if (amount <= 0)
            throw new ArgumentOutOfRangeException(nameof(amount));

        Id = id;
        Amount = amount;
    }
}

public interface IPaymentGateway
{
    string GeneratePaymentUrl(Order order);
}

public interface IHasher
{
    string ComputeHash(string input);
}

public class MD5Hasher : IHasher
{
    public string ComputeHash(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            throw new ArgumentException(nameof(input));

        using MD5 md5 = MD5.Create();
        byte[] hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
    }
}

public class SHA1Hasher : IHasher
{
    public string ComputeHash(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            throw new ArgumentException(nameof(input));

        using SHA1 sha1 = SHA1.Create();
        byte[] hashBytes = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
    }
}

public class BasicPaymentGateway : IPaymentGateway
{
    private readonly IHasher _hasher;

    public BasicPaymentGateway(IHasher hasher)
    {
        _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
    }

    public string GeneratePaymentUrl(Order order)
    {
        if (order == null)
            throw new ArgumentNullException(nameof(order));

        string transactionHash = _hasher.ComputeHash(order.Id.ToString());
        return $"https://pay.system1.ru/order?amount={order.Amount}RUB&hash={Uri.EscapeDataString(transactionHash)}";
    }
}

public class AmountAwarePaymentGateway : IPaymentGateway
{
    private readonly IHasher _hasher;

    public AmountAwarePaymentGateway(IHasher hasher)
    {
        _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
    }

    public string GeneratePaymentUrl(Order order)
    {
        if (order == null)
            throw new ArgumentNullException(nameof(order));

        string combinedData = $"{order.Id}{order.Amount}";
        string verificationHash = _hasher.ComputeHash(combinedData);
        return $"https://order.system2.ru/pay?hash={Uri.EscapeDataString(verificationHash)}";
    }
}

public class SecurePaymentGateway : IPaymentGateway
{
    private readonly IHasher _hasher;
    private readonly string _apiSecret;

    public SecurePaymentGateway(IHasher hasher, string apiSecret)
    {
        _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));

        if (string.IsNullOrWhiteSpace(apiSecret))
            throw new ArgumentException(nameof(apiSecret));

        _apiSecret = apiSecret;
    }

    public string GeneratePaymentUrl(Order order)
    {
        if (order == null)
            throw new ArgumentNullException(nameof(order));

        string securePayload = $"{order.Amount}{order.Id}{_apiSecret}";
        string encryptedSignature = _hasher.ComputeHash(securePayload);
        return $"https://system3.com/pay?amount={order.Amount}&currency=RUB&hash={Uri.EscapeDataString(encryptedSignature)}";
    }
}
