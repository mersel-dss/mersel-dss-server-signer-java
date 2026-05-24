using System.Net;
using MERSEL.Services.DssSigner.Client.Models;

namespace MERSEL.Services.DssSigner.Client.Exceptions;

/// <summary>
/// DSS Signer API'sinden başarısız bir HTTP yanıtı geldiğinde fırlatılır.
/// Sunucunun döndürdüğü yapılandırılmış <see cref="DssSignerError"/>
/// (varsa) <see cref="ApiError"/> üzerinden erişilebilir.
/// </summary>
public sealed class DssSignerApiException : Exception
{
    /// <summary>HTTP durum kodu.</summary>
    public HttpStatusCode StatusCode { get; }

    /// <summary>Sunucu yanıtının deserialize edilmiş hata gövdesi (varsa).</summary>
    public DssSignerError? ApiError { get; }

    /// <summary>Sunucu yanıtının ham gövdesi (yapılandırılmış parse başarısız olduysa loglama için).</summary>
    public string? RawBody { get; }

    /// <summary>İstek atılan endpoint yolu (debug/log amaçlı).</summary>
    public string? RequestPath { get; }

    public DssSignerApiException(
        HttpStatusCode statusCode,
        string message,
        DssSignerError? apiError = null,
        string? rawBody = null,
        string? requestPath = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        StatusCode = statusCode;
        ApiError = apiError;
        RawBody = rawBody;
        RequestPath = requestPath;
    }
}
