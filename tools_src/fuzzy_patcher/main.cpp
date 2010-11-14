#include <stdio.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>

#include <vector>
#include <utility>
#include <algorithm>
#include <string>
#include <iostream>
#include <sstream>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <boost/iostreams/device/mapped_file.hpp>

typedef std::pair<float, size_t> ratingAtPos;
typedef std::vector<ratingAtPos> ratingsVector;
typedef std::vector<unsigned char> byteString;

static int g_fuzzLevel = 100;
static bool g_verbose = false;

std::string bytes2hex(byteString bytes) 
{
	std::stringstream buf;
	for (size_t i = 0; i < bytes.size(); ++i) {
		if (i != 0) {
			buf << " ";
		}
		buf << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)bytes[i] << std::dec;
	}
	return buf.str();
}

byteString hex2bytes(std::string hex)
{
	byteString result;
	std::istringstream s(hex);
	while (!s.eof()) {
		unsigned int n;
		s >> std::hex >> n;
		result.push_back((unsigned char)n);
	}
	return result;
}

static unsigned char diff_byte_rating[0x100];

void init_diff_byte_rating()
{
	static bool inited = false;
	if (inited)
		return;
	inited = true;

	for (unsigned int i = 0; i < sizeof(diff_byte_rating)/sizeof(diff_byte_rating[0]); ++i) {
		unsigned int count = 0;
		unsigned int t = i;
		while (t) { 
			++count;
			t >>= 1;
		}
		unsigned int rating = 8 - count;

		if (count == 0)  {
			rating += 8;
		} else if ((i & 0x0F) == 0|| ((i & 0xF0) == 0)) {
			rating += 4;
		}
		diff_byte_rating[i] = rating;
	}
}

__inline float correlate(const unsigned char* p1, const unsigned char* p2, size_t len, float* weight) 
{
	float sum = 0;
	for (size_t i = 0; i < len; ++i) {
		sum += weight[i] * diff_byte_rating[p1[i] ^ p2[i]];
	}
	return sum;
}

std::vector<float>weightVector(size_t size, size_t patchStart, size_t patchSize)
{
	auto patchEnd = patchStart - patchSize;
	std::vector<float>weightVector(size, 0.0f);
	for (size_t i = 0; i < size; ++i) {
		float weightValue;
		if (i < patchStart) {
			weightValue = 1.0f / sqrt(1.0f + patchStart - i);
		} else if (i < patchStart + patchSize) {
			weightValue = 1.0f;
		} else {
			weightValue = 1.0f / sqrt(2.0f + i - (patchStart + patchSize));
		}
		weightVector[i] = weightValue;
	}
	return weightVector;
}

std::vector<ratingsVector> calculate_top_matches(
	boost::iostreams::mapped_file_source image,
	size_t top_size,
	std::vector<byteString> patterns,
	std::vector<std::pair<int,int>> patchLocations
	) 
{
	const size_t step_size = 1000;
	const size_t vector_size = top_size + step_size;

	const ratingAtPos defaultRating(0, 0);
	const ratingsVector defaultRatingsVector(vector_size, defaultRating);
	
	std::vector<ratingsVector> ratingsVectors(patterns.size(), defaultRatingsVector);

	std::vector<std::vector<float>> weightVectors;

	for (unsigned int i = 0; i < patchLocations.size(); ++i) {
		auto &pl = patchLocations[i];
		weightVectors.push_back(weightVector(patterns[i].size(), pl.first, pl.second));
	}

	for (unsigned int j = 0; j <= image.size() / step_size; ++j) {
		for (unsigned int n = 0; n < patterns.size(); ++n) {
			auto &pat = patterns[n];
			auto &v = ratingsVectors[n];
			auto &weight = weightVectors[n];
			size_t pos_base = j * step_size;
			size_t adjustedSize = image.size() - pat.size();
			if (pos_base >= adjustedSize)
				continue;
			size_t adjustedStepSize = adjustedSize - pos_base;
			if (adjustedStepSize > step_size)
				adjustedStepSize = step_size;
			for (size_t i = 0; i < adjustedStepSize; ++i) {
				ratingAtPos &p = v[i + top_size];
				size_t pos = i + pos_base;

				p.first = correlate(reinterpret_cast<const unsigned char*>(image.data() + pos), pat.data(), pat.size(), weight.data());
				p.second = pos;
			}
			std::partial_sort(v.begin(), v.begin() + top_size, v.end(), [](ratingAtPos& v1, ratingAtPos& v2){return v1.first > v2.first;});
		}
	}

	for (unsigned int n = 0; n < patterns.size(); ++n) {
		auto &pat = patterns[n];
		auto &v = ratingsVectors[n];
		v.resize(top_size);
		float calibration = 1.0f / correlate(pat.data(), pat.data(), pat.size(), weightVectors[n].data());
		for ( auto i = v.begin(); i != v.end(); ++i) {
			i->first *= calibration;
		}
	}
	return ratingsVectors;
}

class patch {
protected:
        byteString matchBytes;
        byteString patchBytes;
        int patchOffset;
        double secondMatchCorrelation;
        double adjustedSecondMatchCorrelation;
		size_t origOffset;
public:
	patch(boost::iostreams::mapped_file_source origImage, const unsigned char* pPatched, size_t start, size_t end);
	patch(boost::property_tree::ptree node);
	~patch();

	boost::property_tree::ptree ptreeNode();
	byteString PatternBytes();
	byteString PatchBytes();
	int PatchOffset();

	static const int MinMatchSize = 0x10;
    static const int MaxPatchSize = 0x100;
    static const int MinPatchGap = 4;
	static float MaxSecondMatchCorrelation;
};

float patch::MaxSecondMatchCorrelation = .8f;

patch::patch(boost::iostreams::mapped_file_source origImage, const unsigned char* pPatched, size_t start, size_t end)
{
	const size_t len = end - start;
	const unsigned char* pOrig = reinterpret_cast<const unsigned char*>(origImage.data());
	adjustedSecondMatchCorrelation = 2.0f;
	size_t extend = len > 16 ? 0 : 8;
	for (;;) { 
		std::vector<byteString> patterns;
		if (extend > start) 
			throw std::exception("Start of file hit while extending the match pattern!");
		size_t newStart = start - extend;
		size_t newEnd = end + extend;
		if (newEnd > origImage.size()) 
			throw std::exception("End of file hit while extending the match pattern!");
		patterns.push_back(byteString(pOrig + newStart, pOrig + newEnd));
		std::vector<std::pair<int,int>> patchLocations;
		patchLocations.push_back(std::pair<int, int>(extend, end - start));
		auto ratings = calculate_top_matches(origImage, 2, patterns, patchLocations);
		secondMatchCorrelation = ratings[0][1].first;
		float extendBasedAdjustmentCoefficient = pow(extend / 16.0f, 2);
		adjustedSecondMatchCorrelation = pow(secondMatchCorrelation, 1.0 + extendBasedAdjustmentCoefficient);
		if (g_verbose) {
			std::cout << "patch::patch(): extend:" << extend << 
				"; secondMatchCorrelation:" << secondMatchCorrelation << 
				"; adjustedSecondMatchCorrelation=" << adjustedSecondMatchCorrelation << std::endl;
		}
		if (adjustedSecondMatchCorrelation < MaxSecondMatchCorrelation) {
			break;
		}
		if (extend == 0)
			extend = 1;
		else 
			extend <<= 1;
	}
	matchBytes.assign(pOrig + start - extend, pOrig + end + extend);
	patchBytes.assign(pPatched + start, pPatched + end);
	patchOffset = extend;
	origOffset = start;
}

patch::~patch()
{
}

patch::patch(boost::property_tree::ptree patchElem)
{
	matchBytes = hex2bytes(patchElem.get<std::string>("patternBytes"));
	patchBytes = hex2bytes(patchElem.get<std::string>("patchBytes"));
	patchOffset = patchElem.get<int>("patchOffset");
}

boost::property_tree::ptree patch::ptreeNode() 
{
	boost::property_tree::ptree patchElem;
	patchElem.put<std::string>("patternBytes", bytes2hex(matchBytes));
	patchElem.put<std::string>("patchBytes", bytes2hex(patchBytes));
	patchElem.put<int>("patchOffset", patchOffset);
	patchElem.put<long double>("secondMatchCorrelation", secondMatchCorrelation);
	patchElem.put<long double>("adjustedSecondMatchCorrelation", adjustedSecondMatchCorrelation);
	std::stringstream comment;
	comment << "Original offset: " << std::hex << origOffset;
	patchElem.put<std::string>("comment", comment.str());
	return patchElem;
}

byteString patch::PatternBytes() {
	return matchBytes;
}

byteString patch::PatchBytes() {
	return patchBytes;
}

int  patch::PatchOffset()
{
	return patchOffset;
}

void diffFiles(const std::string origPath, const std::string patchedPath, const std::string deltaPath) 
{
	auto orig = boost::iostreams::mapped_file_source(origPath);
	auto patched = boost::iostreams::mapped_file_source(patchedPath);

	if (orig.size() != patched.size()) {
		std::cerr << "Orig and patched file must be of the same size!";
		exit(1);
	}

	std::vector<patch> patches;

	bool inPatch = false;
	size_t patchStart = -1;
	size_t patchEnd = -1;
	const unsigned char* pOrig = reinterpret_cast<const unsigned char*>(orig.data());
	const unsigned char* pPatched = reinterpret_cast<const unsigned char*>(patched.data());
	for (size_t i = 0; i < orig.size(); ++i) {
		bool diff = pOrig[i] != pPatched[i];
		if (!inPatch && diff) {
			patchStart = i;
			inPatch = true;
		} 
		if (inPatch && diff) {
			patchEnd = i + 1;
		} else if (inPatch && !diff) {
			if (patchEnd + patch::MinPatchGap < i) {
				patch p(orig, pPatched, patchStart, patchEnd);
				patches.push_back(p);
				inPatch = false;
			}
		}
	}

	if (inPatch) {
		throw std::exception("Last change too close to EOF!"); 
	}

	boost::property_tree::ptree tree;
	boost::property_tree::ptree patchesNode;
	for (auto p = patches.begin(); p != patches.end(); ++p) {		
		patchesNode.push_back( std::make_pair("", p->ptreeNode()) );
	}
	tree.put_child("patches", patchesNode);

	boost::property_tree::json_parser::write_json(deltaPath, tree);
}

void topX(const ratingsVector &r, int patchOffset) 
{
	std::cout << "Top" << r.size() << ": " << std::endl;
	for (unsigned int j = 0; j < r.size(); ++j) {
		const ratingAtPos &x = r[j];
		std::cout << x.first << " at " << std::hex << x.second + patchOffset << std::dec << std::endl;		
	}
}

void patchFiles(const std::string origPath, const std::string patchedPath, const std::string deltaPath) 
{
	auto orig = boost::iostreams::mapped_file_source(origPath);
	boost::iostreams::mapped_file_params params;
	params.new_file_size = orig.size();
	params.path = patchedPath;
	auto patched = boost::iostreams::mapped_file_sink(params);
	memcpy(patched.data(), orig.data(), orig.size());
	
	boost::property_tree::ptree tree;
	boost::property_tree::json_parser::read_json(deltaPath, tree);

	std::vector<patch>patches;
	boost::property_tree::ptree patchesNode = tree.get_child("patches");
	for (auto p = patchesNode.begin(); p != patchesNode.end(); ++p) {		
		patches.push_back(patch(p->second));
	}
	if (g_verbose) {
		std::cout << patches.size() << " patches loaded" << std::endl;
	}
	std::vector<byteString> patterns;
	std::vector<std::pair<int,int>> patchLocations;
	for (auto p = patches.begin(); p != patches.end(); ++p) {
		patterns.push_back(p->PatternBytes());
		patchLocations.push_back(std::pair<int,int>(p->PatchOffset(), p->PatchBytes().size()));
	}

	const int topSize = 5;

	auto matches = calculate_top_matches(orig, topSize, patterns, patchLocations);
	for (unsigned int i = 0; i < matches.size(); ++i) {
		ratingsVector &r = matches[i];
		patch &p = patches[i];
		std::cout << "Patch " << i + 1 << std::endl;
		float exact = .9999f;
		bool fApply = false;
		if (r[0].first < exact) {
			std::cout << "No exact match" << std::endl;
			topX(r, p.PatchOffset());
			if (100.0 * r[0].first > g_fuzzLevel)
				fApply = true;
		} else if (r[1].first >= exact) {
			std::cout << "Multiple matches" << std::endl;
			topX(r, p.PatchOffset());
		} else {
			std::cout << "Exactly one match at " << std::hex << r[0].second + p.PatchOffset() << std::dec << std::endl;
			fApply = true;
		}
		if (fApply) {
			memcpy(patched.data() + r[0].second + p.PatchOffset(), p.PatchBytes().data(), p.PatchBytes().size());
		}
	}
}

int main(int argc, char** argv) {	
	init_diff_byte_rating();

	// Declare the supported options.
	po::options_description desc("Allowed options");
	desc.add_options()
		("help", "produce help message")
		("diff", "produce a difference file")
		("patch", "patch the original using the difference file")
		("delta", po::value<std::string>()->required(), "difference file")
		("orig", po::value<std::string>()->required(), "original file")
		("patched", po::value<std::string>()->required(), "patched file")
		("fuzz", po::value<int>()->default_value(100), "fuzzy matching level (0-100), default=100 (disabled)")		
		("verbose", "enable extra logging")
	;

	po::variables_map vm;
	try {
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);
	} catch(std::exception ex) {
		std::cerr << "Argument exception : " << ex.what() << std::endl;
		std::cout << desc << std::endl;
		return 1;
	}

	if (vm.count("help") || (vm.count("diff") + vm.count("patch") == 0)) {
		std::cout << desc << std::endl;
		return 0;
	}

	if (vm.count("fuzz")) {
		g_fuzzLevel = vm["fuzz"].as<int>();
	}
	if (vm.count("verbose")) {
		g_verbose = true;
	}

	std::string orig = vm["orig"].as<std::string>();
	std::string patched = vm["patched"].as<std::string>();
	std::string delta = vm["delta"].as<std::string>();
	
	try {
		if (vm.count("diff")) {
			diffFiles(orig, patched, delta);
		} else if (vm.count("patch")) {
			patchFiles(orig, patched, delta);
		}
	} catch (std::exception ex) {
		std::cerr << "Error: " << ex.what() << std::endl;
		exit(1);
	}
	return 0;
}