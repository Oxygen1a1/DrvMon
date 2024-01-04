#pragma once

namespace kstd {
#pragma warning(disable : 4996)
	static const long pool_tag = 'func';

	template<typename T>
	struct always_false {
	public:
		static constexpr bool value = false;
	};

	//�����always_false����Ϊ����������ʧ�� �����Ĭ�ϵ�ģ��funtion��,Ĭ��һ���Ǵ���ģ���Ϊ������Ҫ����ģ���ػ�
	template<typename FuncSig>
	struct kfunction {

		static_assert(always_false<FuncSig>::value, "invalid function sig!");

	};

	//����kfunction���ػ�
	template<typename Ret, typename... Args>
	struct kfunction<Ret(Args...)/*������ͲŲ��ᴥ����̬����*/> {

	private:
		/*�ṩ�ӿ�,����FuncType��������������ģ��*/
		struct FuncBase {
			virtual Ret call(Args... args) = 0;
			virtual ~FuncBase() = default;
			void operator delete (void* p,size_t size) {
				//���붨�� ��ΪFuncIpml�������� �ں�û��ȫ��delete!! ����ɶ�����ø� ��Ϊ�����û��������new
				//���Ǳ����ʵ��! Ϊʲô��? ��Ϊ���Ǳ��������������ָ��,���������������������������Ǹ�������,���ջ�
				//�������FuncImpl!
				__debugbreak();
				UNREFERENCED_PARAMETER(p);
				UNREFERENCED_PARAMETER(size);
			}
		};

		/*��̬*/
		template<typename FuncType>
		struct FuncImpl : FuncBase {
		public:
			FuncImpl(FuncType func) : __func(func){}

			virtual Ret call(Args... args) override {
				
				return __func(args...);/*���ﲻ��������ת�� �ں�û��std::forward*/
				
			}
			
			/*�ڲ�����new*/
			void* operator new(size_t size) {
				return ExAllocatePoolWithTag(NonPagedPool, size, pool_tag);
			}
			
			void operator delete(void* p, size_t size) {
				
				if (p != nullptr && size != 0) {
					ExFreePool(p);
				}
			}

			FuncType __func;

		};

	public:

		kfunction():__fb(nullptr){}

		template<typename FuncType>
		kfunction(FuncType ft) : kfunction() {

			__fb = new FuncImpl<FuncType>(ft);
		}

		Ret operator()(Args&&... args) {
			if (__fb != nullptr)
				return __fb->call(args...);
			else return Ret();
		}

		~kfunction() {
			
			if (__fb) {
				delete __fb;
				__fb = nullptr;
			}
				
		}
	private:
		FuncBase* __fb;
	};

#pragma warning(default : 4996)
}