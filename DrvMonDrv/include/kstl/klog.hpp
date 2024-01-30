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
		
	private:

	};

	NTSTATUS inline Logger::logPrint(LogLevel log_level, const char* function_name, const char* format, ...)
	{
		auto status =STATUS_SUCCESS;
		char log_message[412]{};
		va_list args{};
		va_start(args, format);

		status = RtlStringCchVPrintfA(log_message, sizeof log_message, format, args);

		va_end(args);

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



}

#pragma warning(default : 4996)

#endif // !_KLOG_H_


