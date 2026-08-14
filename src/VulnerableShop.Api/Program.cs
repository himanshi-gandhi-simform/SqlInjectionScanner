using Microsoft.EntityFrameworkCore;
using VulnerableShop.Api.Data;
using VulnerableShop.Api.Services;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("ShopDb")
    ?? "Server=(localdb)\\mssqllocaldb;Database=VulnerableShop;Trusted_Connection=True;TrustServerCertificate=True";

builder.Services.AddControllers();
builder.Services.AddDbContext<ShopDbContext>(options => options.UseSqlServer(connectionString));

builder.Services.AddSingleton(new SqlConnectionFactory(connectionString));
builder.Services.AddScoped<AdoNetProductRepository>();
builder.Services.AddScoped<DapperOrderRepository>();
builder.Services.AddScoped<EfCoreCustomerRepository>();
builder.Services.AddScoped<ReportQueryBuilder>();
builder.Services.AddScoped<AuditService>();

var app = builder.Build();

app.MapControllers();

app.Run();
