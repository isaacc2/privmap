def WeatherClassification( temperature_c , rain_mm , aqi ):
	"""
	Classify weather conditions based on temperature, rainfall, and AQI. 
	Weather is classified as 'CRITICAL', 'WARNING', 'NORMAL', or 'INVALID'.

    Args:
        temperature_c (float): The user inputted temperature in Celsius.
        rain_mm (float): The user inputted rainfall in millimeters.
        aqi (int): The user inputted Air Quality Index.

    Returns:
        tuple: A tuple containing the system status and a list of reasons.
		system_status (str): The overall classification of the weather conditions.
		reasons (list): The list of reasons that justify the classification.
    """

	reasons = []
	system_status = 'UNKNOWN'

	#validate inputs, throw helpful error and return if an input is invalid
	if not -50 <= temperature_c <= 60:
		reasons.append("invalid temperature")
		system_status = 'INVALID'
	if not 0 <= rain_mm <= 500:
		reasons.append("invalid rain_mm")
		system_status = 'INVALID'
	if not 0 <= aqi <= 500:
		reasons.append('invalid aqi')
		system_status = 'INVALID'

	if system_status == 'INVALID':
		return system_status, reasons



	#Determine if status is critical, 
	if not -10 <= temperature_c <= 45:
		reasons.append("The temperature is below -10 or above 45")
		system_status = 'CRITICAL'
	if 120 < rain_mm:
		reasons.append("The rainfall exceeds 120mm")
		system_status = 'CRITICAL'
	if 150 < aqi:
		reasons.append("The aqi exceeds 150")
		system_status = 'CRITICAL'

	if system_status == 'CRITICAL':
		return system_status, reasons

	#Determine if readings matches conditions for a warning
	if not 0 <= temperature_c <= 35:
		reasons.append("The temperature is below 0 or above 35")
		system_status = 'WARNING'
	if 50 < rain_mm <= 120:
		reasons.append("The rainfall is greater than 50 up to 120")
		system_status = 'WARNING'
	if 101 <= aqi <= 150:
		reasons.append("The aqi is within 101 to 150")
		system_status = 'WARNING'

	if system_status == "WARNING":
		return system_status, reasons

	#weather is normal since there are no warnings
	system_status = 'NORMAL'
	reasons.append("All measurements within safe range")
	return system_status, reasons

# example usage
temperature_c = float(input("enter a temperature in celcius: "))
rain_mm = float(input("enter rainfall in mm: "))
aqi = int(input("enter aqi: "))
print(f'\n{"temperature_c":<15} | {"rain_mm":<10} | {"aqi":<10}')
print(f"{temperature_c:<15} | {rain_mm:<10} | {aqi:<10}\n")

# display the system status and reasons
status, reasons = WeatherClassification(temperature_c, rain_mm, aqi)
print(f"Status: {status}")
print(f"Reasons: {', '.join(reasons)}")