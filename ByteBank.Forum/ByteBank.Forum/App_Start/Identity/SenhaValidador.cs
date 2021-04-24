﻿using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace ByteBank.Forum.App_Start.Identity
{
    public class SenhaValidador : IIdentityValidator<string>
    {
        public int TamanhoRequerido { get; set; }
        public bool ObrigatorioCaracteresEspeciais { get; set; }
        public bool ObrigatorioLowerCase { get; set; }
        public bool ObrigatorioUpperCase { get; set; }
        public bool ObrigatorioDigitos { get; set; }

        public async Task<IdentityResult> ValidateAsync(string item)
        {
            var erros = new List<string>();

            if (!VerificaTamanhoRequerido(item))
                erros.Add($"A senha deve conter pelo menos {TamanhoRequerido} caracteres");

            if (ObrigatorioCaracteresEspeciais && !VerificaCaracteresEspeciais(item))
                erros.Add("A senha deve conter caracteres especiais");

            if (ObrigatorioLowerCase && !VerificaLowerCase(item))
                erros.Add("A senha deve conter caracteres minusculos");

            if (ObrigatorioUpperCase && !VerificaUpperCase(item))
                erros.Add("A senha deve conter caracteres maiusculos");

            if (ObrigatorioDigitos && !VerificaDigito(item))
                erros.Add("A senha deve conter digitos");

            if (erros.Any())
                return IdentityResult.Failed(erros.ToArray());
            else
                return IdentityResult.Success;
        }

        private bool VerificaTamanhoRequerido(string senha) =>
            senha?.Length >= TamanhoRequerido;

        private bool VerificaCaracteresEspeciais(string senha) =>
            Regex.IsMatch(senha, @"[~`!@#$%^&*()+=|\\{}':;.,<>/?[\]""_-]");

        private bool VerificaLowerCase(string senha) =>
            senha.Any(char.IsLower);

        private bool VerificaUpperCase(string senha) =>
            senha.Any(char.IsUpper);

        private bool VerificaDigito(string senha) =>
            senha.Any(char.IsDigit);
    }
}