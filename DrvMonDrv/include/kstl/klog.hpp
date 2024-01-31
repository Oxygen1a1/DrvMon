#pragma once
#ifndef _KLOG_H_
#define  _KLOG_H_

//a vert simple log lib

#include <fltKernel.h>
#include <ntstrsafe.h>
#pragma prefast(disable : 30030)
#pragma warning(disable: 4996)

namespace kstd {


#define LOG_DEBUG(format,...) \
	kstd::Logger::logPrint(kstd::Logger::LogLevel::Debug,__FUNCTION__,format,__VA_ARGS__)
#define LOG_INFO(format,...) \
	kstd::Logger::logPrint(kstd::Logger::LogLevel::Info,__FUNCTION__,format,__VA_ARGS__)
#define LOG_ERROR(format,...) \
	kstd::Logger::logPrint(kstd::Logger::LogLevel::Error,__FUNCTION__,format,__VA_ARGS__)


	class Logger {
	public:
		enum class LogLevel {
			Debug,
			Info,
			Error
		};
	public:
		static NTSTATUS logPrint(LogLevel log_level, const char* function_name,const char* format, ...);
		static void getCurSystemTime(char* buf, size_t size);
	private:
		
	};

	NTSTATUS inline Logger::logPrint(LogLevel log_level, const char* function_name, const char* format, ...)
	{
		auto status = STATUS_SUCCESS;
		char log_message[412]{};
		char time[100]{};
		va_list args{};
		va_start(args, format);

		status = RtlStringCchVPrintfA(log_message, sizeof log_message, format, args);

		va_end(args);

		getCurSystemTime(time, sizeof time);
		DbgPrintEx(77, 0, "%s\t", time);

		if (NT_SUCCESS(status)) {
			if (log_level == LogLevel::Debug) {
				DbgPrintEx(77, 0, "[debug]\tfunction name:%s\t", function_name);
			}
			else if(log_level==LogLevel::Error) {
				DbgPrintEx(77, 0, "[error]\t");
			}
			else {
				DbgPrintEx(77, 0, "[Info]\t");
			}

			DbgPrintEx(77, 0, log_message);
		}

		return status;
	}

	inline void Logger::getCurSystemTime(char* buf, size_t size)
	{
		LARGE_INTEGER sys_time{}, loacal_time{};
		TIME_FIELDS time_fields{};

		KeQuerySystemTime(&sys_time.QuadPart);
		ExSystemTimeToLocalTime(&sys_time, &loacal_time);
		RtlTimeToTimeFields(&loacal_time, &time_fields);
		sprintf_s(buf, size, "[%4d-%2d-%2d %2d:%2d:%2d:%3d]", time_fields.Year, time_fields.Month, time_fields.Day,
			time_fields.Hour, time_fields.Minute, time_fields.Second, time_fields.Milliseconds);

	}



}

#pragma warning(default : 4996)

#endif // !_KLOG_H_


