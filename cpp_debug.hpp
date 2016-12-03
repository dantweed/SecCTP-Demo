#ifndef CPP_DEBUG_HPP
#define CPP_DEBUG_HPP

#ifdef DEBUG
	#define debug_message(...) cerr, __VA_ARGS__, endl
	#define on_error(...) {debug_message(__VA_ARGS__); exit(EXIT_FAILURE);}
#else
	#define debug_message(...){}
	#define on_error(...) cerr, __VA_ARGS__, endl
#endif
template <typename T>
std::ostream& operator,(std::ostream& out, const T& t) {
  out << t;
  return out;
}

//overloaded version to handle all those special std::endl and others...
std::ostream& operator,(std::ostream& out, std::ostream&(*f)(std::ostream&)) {
  out << f;
  return out;
}

#endif
