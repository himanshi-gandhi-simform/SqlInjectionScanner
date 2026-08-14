namespace VulnerableShop.Api.Models;

public class Product
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public decimal Price { get; set; }
}

public class Order
{
    public int Id { get; set; }
    public int CustomerId { get; set; }
    public string Status { get; set; } = string.Empty;
    public DateTime PlacedOn { get; set; }
    public decimal Total { get; set; }
}

public class Customer
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public string Region { get; set; } = string.Empty;
    public bool IsActive { get; set; }

    /// <summary>Free-text field editable by the customer through their profile page.</summary>
    public string Notes { get; set; } = string.Empty;
}

public class ReportFilter
{
    public string? Category { get; set; }
    public string? Region { get; set; }
    public string? SortColumn { get; set; }
    public string? SortDirection { get; set; }
    public int PageSize { get; set; } = 50;
}
