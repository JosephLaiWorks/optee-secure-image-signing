#ifndef VERIFY_SIGNATURE_H
#define VERIFY_SIGNATURE_H

void verify_all_images(const char *img_dir, const char *sig_dir,
                      const char *mod_path, const char *exp_path);
                      
void verify_one_image(const char *img_path, const char *sig_path,
                      const char *mod_path, const char *exp_path);

#endif

