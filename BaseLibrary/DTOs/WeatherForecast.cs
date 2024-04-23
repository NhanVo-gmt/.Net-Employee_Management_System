﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BaseLibrary.DTOs
{
    public class WeatherForecast
    {
        public DateOnly Date {  get; set; }
        public int TemperatureC {  get; set; }
        public int TemperatureF => 32 + (int)(TemperatureC / 0.556);
        public string? Summary {  get; set; }
    }
}
