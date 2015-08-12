
#ifndef SCRB_COMMON_H_
#define SCRB_COMMON_H_

enum GNUNET_SCRB_ContentType
{
  MSG, ANYCAST_MSG, MULTICAST_MSG, DHT_PUT
};

/**
 * Content of a scribe message
 */
struct GNUNET_SCRB_Content
{
  /**
   * Data
   */
  char* data;
  /**
   * Size
   */
  size_t data_size;
  /**
   * Content type
   */
  enum GNUNET_SCRB_ContentType type;
};

#endif /* SCRB_COMMON_H_ */
