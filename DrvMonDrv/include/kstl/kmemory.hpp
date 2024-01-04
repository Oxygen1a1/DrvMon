#pragma once
#include <fltKernel.h>

/// <summary>
/// ʵ������stl��<memory> ���˸��Լ�ʵ�ֵ�kstd::move �����ƶ�����!!
/// </summary>
namespace kstd {
#pragma warning(disable : 4996)
	static constexpr unsigned long km_pool_tag = 'Uptr';

	template<typename T>
	T&& move(T& v) {
		return static_cast<T&&>(v);
	}


	/*����������Լ�ʵ��new �� delete ���ǲ���ȫ�ֵ� ������ɵ�ȱ������޷�new ����?*/
	namespace inner{
		template<typename T,typename... Args>
		T* __new(Args&&... args) {
			auto p = reinterpret_cast<T*>(ExAllocatePoolWithTag(NonPagedPool, sizeof(T), km_pool_tag));
			if (p != nullptr) {
				*p =T(args...);/*���������ǽ���ֵ ����Զ������ƶ�����?*/
			}
			return p;
		}

		template<typename T>
		void __delete(T* p)
		{
			if (p != nullptr) {
				ExFreePool(p);
			}
		}
	}

	template<typename T>
	struct DefaultDeleter {
		void operator() (T* p) {
			inner::__delete(p);
		}
	};

	//ƫ�ػ� ȥ����
	//template<typename T>
	//struct DefaultDeleter<T[]> {

	//};
	//���Ծ���ȫ�ػ� ĳЩ�ض���,����HANDLE 
	//template<>
	//struct DefaultDeleter<HANDLE> {

	//};

	template<class T, class Deleter = DefaultDeleter<T>>
	struct unique_ptr {


	public:
		unique_ptr() : __p(nullptr) {}

		unique_ptr(T* p) :__p(p) {}

		unique_ptr(const unique_ptr& rhs) = delete;/*��ͨ�Ŀ����������ɾ��*/
		unique_ptr& operator= (const unique_ptr& rhs) = delete;

		//�ƶ�����
		unique_ptr(unique_ptr&& rhs) {
			if (&rhs != this) {
				if (__p) {
					reset();/*�����õ�ԭ���е�*/
				}
				this->__p = rhs.release();
			}
		}

		//�ƶ�����
		unique_ptr& operator=  (unique_ptr&& rhs) {
			if (&rhs != this) {
				if (__p) {
					reset();/*�����õ�ԭ���е�*/
				}
				this->__p = rhs.release();
			}

			return *this;
		}

		//DTOR
		~unique_ptr() {
			if (__p)
				Deleter{}(__p);
		}

		/*��ȡ��ǰ�洢����Դ*/
		T* get() const { return __p; }

		/*ת�Ƶ�ǰ�洢����Դ*/
		T* release() {
			auto tmp = __p;
			__p = nullptr;
			return tmp;
		}

		/*�ͷŵ�ǰ�洢����Դ*/
		void reset(T* p = nullptr) {
			if (__p)
				Deleter{}(__p);
			__p = p;
		}

		//����-> �� * ������ ����ÿ���������ܱر���
		T& operator*() const {
			return *__p;
		}

		T* operator-> () const {
			return __p;
		}

	private:
		T* __p;
	};


	//make unique_ptr Ҳ�Ǳر���
	template<typename T, typename... Args>
	unique_ptr<T> make_unique(Args&&... args) {
		return unique_ptr<T>(inner::__new<T>(args...));
	}

#pragma warning(default : 4996)
}