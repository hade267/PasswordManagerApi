using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PasswordManagerApi.Migrations
{
    /// <inheritdoc />
    public partial class AddMFA : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "MFASecret",
                table: "Users",
                type: "longtext",
                nullable: false)
                .Annotation("MySql:CharSet", "utf8mb4");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "MFASecret",
                table: "Users");
        }
    }
}
