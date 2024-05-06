#include <cstdio> // For popen, pclose
#include <sstream> // For istringstream
#include <stdexcept> // For runtime_error
#include <string> // For string handling
#include <vector> // For vector
#include <memory> // For unique_ptr

#include <boost/algorithm/string.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/networking/posix/utils.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace osquery {
namespace tables {

struct DNSResolver {
  std::string index;
  std::string domain;
  std::string ifIndex;
  std::string flags;
  std::string reach;
  std::string order;
  std::string timeout;
  std::vector<std::string> nameservers;
  std::vector<std::string> searchDomains;
};

// Function to execute a shell command and return its output
std::string executeShellCommand(const char* cmd) {
  std::array<char, 128> buffer;
  std::string result;
  std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
  if (!pipe) {
    LOG(ERROR) << "popen() failed!";
    throw std::runtime_error("Failed to open pipe for command execution.");
  }
  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    result += buffer.data();
  }
  return result;
}

bool containsSubstring(const std::string& key, const std::string& keyValue) {
  return key.find(keyValue) != std::string::npos;
}

std::vector<DNSResolver> parseDNSOutput(const std::string& output) {
  std::vector<DNSResolver> resolvers;
  std::istringstream stream(output);
  std::string line;
  DNSResolver currentResolver;

  while (getline(stream, line)) {
    if (containsSubstring(line, "resolver #")) {
      if (!currentResolver.index.empty()) {
        resolvers.push_back(currentResolver);
        currentResolver = DNSResolver();
      }
      currentResolver.index = line.substr(line.find_first_of("#") + 1);
      continue;
    }

    size_t pos = line.find_first_of(":");
    if (pos != std::string::npos) {
      std::string key = line.substr(0, pos);
      std::string value = line.substr(pos + 2);

      if (containsSubstring(key, "nameserver")) {
        currentResolver.nameservers.push_back(value);
      } else if (containsSubstring(key, "search domain")) {
        currentResolver.searchDomains.push_back(value);
      } else if (containsSubstring(key, "domain")) {
        currentResolver.domain = value;
      } else if (containsSubstring(key, "if_index")) {
        currentResolver.ifIndex = value.substr(0, value.find_last_not_of(" ") + 1);
      } else if (containsSubstring(key, "flags")) {
        currentResolver.flags = value;
      } else if (containsSubstring(key, "reach")) {
        currentResolver.reach = value;
      } else if (containsSubstring(key, "order")) {
        currentResolver.order = value;
      } else if (containsSubstring(key, "timeout")) {
        currentResolver.timeout = value;
      }
    }
  }
  if (!currentResolver.index.empty()) {
    resolvers.push_back(currentResolver);
  }

  return resolvers;
}

QueryData genDNSConfiguration(QueryContext& context) {
  QueryData results;

  try {
    std::string output = executeShellCommand("scutil --dns");
    std::vector<DNSResolver> resolvers = parseDNSOutput(output);

    for (const auto& resolver : resolvers) {
      Row r;
      r["resolver_index"] = INTEGER(resolver.index);
      r["interface_index"] = INTEGER(resolver.ifIndex);
      r["flags"] = resolver.flags;
      r["reach"] = resolver.reach;
      r["order"] = INTEGER(resolver.order);
      r["timeout"] = resolver.timeout;
      r["nameservers"] = osquery::join(resolver.nameservers, ", ");
      r["search_domains"] = osquery::join(resolver.searchDomains, ", ");
      results.push_back(r);
    }
  } catch (const std::exception& e) {
    LOG(ERROR) << "Failed running scutil --dns: " << e.what();
  }

  return results;
}

} // namespace tables
} // namespace osquery
