namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// PAdES (PDF) imzalama isteği.
/// </summary>
public sealed class SignPadesRequest
{
    /// <summary>İmzalanacak PDF belgesi.</summary>
    public byte[] Document { get; set; } = Array.Empty<byte>();

    /// <summary>İsteğe bağlı: PDF'e gömülecek ek dosya (attachment) içeriği.</summary>
    public byte[]? Attachment { get; set; }

    /// <summary><see cref="Attachment"/> kullanılıyorsa görünecek dosya adı.</summary>
    public string? AttachmentFileName { get; set; }

    /// <summary>
    /// <c>true</c> ise mevcut imzalı PDF üzerine yeni imza eklenir
    /// (incremental update / append signature). Var olan imzalar geçerli kalır.
    /// </summary>
    public bool AppendMode { get; set; }

    /// <summary>İsteğe konacak multipart dosya adı.</summary>
    public string FileName { get; set; } = "document.pdf";
}
